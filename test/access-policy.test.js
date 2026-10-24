// Fork regression tests: the allow-list that replaced upstream's hardcoded
// loopback fence. Upstream could only ever answer "loopback only"; these cases
// pin the behaviour that decides which peer and Host may reach a destructive
// route, including the Tailscale CGNAT range this fork exists for.
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { accessPolicy, hostAllowed, peerAllowed } from '../src/index.js'

const LOOPBACK = ['127.0.0.0/8', '::1', '::ffff:127.0.0.1']
const TAILNET = ['100.64.0.0/10']

test('upstream default still refuses a LAN peer', () => {
  assert.equal(peerAllowed('127.0.0.1', LOOPBACK), true)
  assert.equal(peerAllowed('::1', LOOPBACK), true)
  assert.equal(peerAllowed('::ffff:127.0.0.1', LOOPBACK), true)
  assert.equal(peerAllowed('100.111.111.88', LOOPBACK), false)
})

test('tailnet CGNAT range admits the bound interface and nothing outside it', () => {
  assert.equal(peerAllowed('100.111.111.88', TAILNET), true)
  assert.equal(peerAllowed('100.64.0.1', TAILNET), true)
  assert.equal(peerAllowed('100.127.255.254', TAILNET), true)
  assert.equal(peerAllowed('100.63.255.255', TAILNET), false)
  assert.equal(peerAllowed('100.128.0.0', TAILNET), false)
  assert.equal(peerAllowed('192.168.1.5', TAILNET), false)
})

test('an exact literal rule matches only that address', () => {
  assert.equal(peerAllowed('100.111.111.88', ['100.111.111.88']), true)
  assert.equal(peerAllowed('100.111.111.89', ['100.111.111.88']), false)
})

test('IPv4-mapped peers compare against IPv4 rules', () => {
  assert.equal(peerAllowed('::ffff:100.111.111.88', TAILNET), true)
})

test('garbage peers and malformed rules are refused, never allowed', () => {
  assert.equal(peerAllowed(undefined, LOOPBACK), false)
  assert.equal(peerAllowed('', LOOPBACK), false)
  assert.equal(peerAllowed('not-an-ip', LOOPBACK), false)
  assert.equal(peerAllowed('100.111.111.88', ['100.64.0.0/99']), false)
  assert.equal(peerAllowed('100.111.111.88', ['/8']), false)
})

test('Host rules ignore the port and the brackets', () => {
  assert.equal(hostAllowed('100.111.111.88:3090', ['100.111.111.88']), true)
  assert.equal(hostAllowed('LOCALHOST:3090', ['localhost']), true)
  assert.equal(hostAllowed('[::1]:3090', ['::1']), true)
  assert.equal(hostAllowed('evil.example:3090', ['100.111.111.88']), false)
  assert.equal(hostAllowed('', ['localhost']), false)
})

test('the config file overrides defaults and is re-read when it changes', () => {
  const home = mkdtempSync(join(tmpdir(), 'dsdel-'))
  const file = join(home, 'delete-session.json')
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    writeFileSync(file, JSON.stringify({ allowPeers: ['100.64.0.0/10'], allowHosts: ['100.111.111.88'], token: 't0k' }))
    let policy = accessPolicy()
    assert.deepEqual(policy.allowPeers, ['100.64.0.0/10'])
    assert.deepEqual(policy.allowHosts, ['100.111.111.88'])
    assert.equal(policy.token, 't0k')

    writeFileSync(file, JSON.stringify({ allowPeers: ['10.0.0.0/8'] }))
    const later = new Date(Date.now() + 5000)
    const { utimesSync } = process.getBuiltinModule('node:fs')
    utimesSync(file, later, later)
    policy = accessPolicy()
    assert.deepEqual(policy.allowPeers, ['10.0.0.0/8'])
    assert.deepEqual(policy.allowHosts, ['localhost', '127.0.0.1', '::1'])
    assert.equal(policy.token, '')
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
  }
})

test('with no config file the policy is exactly upstream', () => {
  const previous = process.env.DSH_HOME
  const previousPeers = process.env.DSH_DELETE_SESSION_ALLOW_PEERS
  delete process.env.DSH_HOME
  delete process.env.DSH_DELETE_SESSION_ALLOW_PEERS
  try {
    const policy = accessPolicy()
    assert.deepEqual(policy.allowPeers, LOOPBACK)
    assert.deepEqual(policy.allowHosts, ['localhost', '127.0.0.1', '::1'])
    assert.equal(policy.token, '')
  } finally {
    if (previous !== undefined) process.env.DSH_HOME = previous
    if (previousPeers !== undefined) process.env.DSH_DELETE_SESSION_ALLOW_PEERS = previousPeers
  }
})
