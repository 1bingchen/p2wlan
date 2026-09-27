import assert from 'node:assert/strict'
import test from 'node:test'
import { readAccountReturn, readResourceReturn, resourceOriginState, resourceTabNavigation, relationshipDetailNavigation, readRelationshipIndexReturn } from '../src/pageState.ts'

const tabs = ['topology', 'devices', 'networks', 'rooms']

test('resource drill-down restores the exact source and its cursor trail without recursive state', () => {
  const first = resourceOriginState({ pathname: '/accounts', search: '?q=alice&cursor=account-2&page=2', state: { cursorHistory: ['', 'account-1'], unrelatedSecret: 'excluded' } })
  const second = resourceOriginState({ pathname: '/accounts/B', search: '?tab=networks&q=office&network_page=3', state: first })
  const third = resourceOriginState({ pathname: '/relationships', search: '?network_id=shared&account_id=B', state: second })
  const relationship = readResourceReturn(third)
  assert.equal(relationship.to, '/relationships?network_id=shared&account_id=B')
  const account = readResourceReturn(relationship.state)
  assert.equal(account.to, '/accounts/B?tab=networks&q=office&network_page=3')
  const list = readResourceReturn(account.state)
  assert.equal(list.to, '/accounts?q=alice&cursor=account-2&page=2')
  assert.deepEqual(list.state.cursorHistory, ['', 'account-1'])
  assert.equal(readResourceReturn(list.state), null)
  assert.ok(!JSON.stringify(third).includes('unrelatedSecret'))
})

test('return navigation rejects external, protocol-relative, backslash and unsupported routes', () => {
  for (const to of ['https://example.com/accounts', '//example.com/accounts', '/\\example.com/accounts', '/login', '/accounts#foreign', '/accounts\n']) {
    assert.equal(readResourceReturn({ resourceOrigins: [{ to }] }), null, to)
  }
})

test('navigation retains at most four sources and a bounded cursor trail', () => {
  let state = {}
  for (let i = 0; i < 12; i++) state = resourceOriginState({ pathname: `/accounts/${i}`, search: '?cursor=current', state: { ...state, cursorHistory: Array.from({ length: 300 }, () => 'c'.repeat(500)) } })
  assert.equal(state.resourceOrigins.length, 4)
  assert.ok(state.resourceOrigins.every((origin) => origin.cursorHistory.join('').length <= 16_384))
  const same = resourceOriginState({ pathname: '/accounts/11', search: '?cursor=current', state })
  assert.equal(same.resourceOrigins.length, 4)
})

test('tabs restore each view filters and cursor trail while repeated activation is a no-op', () => {
  const device = new URLSearchParams('tab=devices&account_id=B&q=vpn&status=offline&cursor=device-2&page=2')
  const initial = { cursorHistory: ['', 'device-1'] }
  assert.equal(resourceTabNavigation(device, initial, '/accounts/B', 'devices', 'devices', 'topology', tabs), null)
  const network = resourceTabNavigation(device, initial, '/accounts/B', 'devices', 'networks', 'topology', tabs)
  const networkQuery = new URLSearchParams(network.search)
  assert.equal(networkQuery.get('account_id'), 'B')
  assert.equal(networkQuery.get('cursor'), null)
  networkQuery.set('q', 'office')
  networkQuery.set('network_page', '3')
  const restored = resourceTabNavigation(networkQuery, network.state, '/accounts/B', 'networks', 'devices', 'topology', tabs)
  assert.equal(new URLSearchParams(restored.search).get('q'), 'vpn')
  assert.equal(new URLSearchParams(restored.search).get('status'), 'offline')
  assert.equal(new URLSearchParams(restored.search).get('cursor'), 'device-2')
  assert.deepEqual(restored.state.cursorHistory, ['', 'device-1'])
})

test('changing account scope cannot restore another account tab cursor or query', () => {
  const saved = resourceTabNavigation(new URLSearchParams('tab=rooms&account_id=A&q=private&room_page=4'), {}, '/networks', 'rooms', 'networks', 'networks', tabs)
  const next = resourceTabNavigation(new URLSearchParams('account_id=B'), saved.state, '/networks', 'networks', 'rooms', 'networks', tabs)
  assert.equal(new URLSearchParams(next.search).get('account_id'), 'B')
  assert.equal(new URLSearchParams(next.search).get('q'), null)
  assert.equal(new URLSearchParams(next.search).get('room_page'), null)
})

test('over-budget tab snapshots are rejected as a whole rather than restoring a cursor with truncated filters', () => {
  const query = new URLSearchParams({ q: 'q'.repeat(5000), resource_q: 'r'.repeat(5000), cursor: 'bound-to-original-query', tab: 'devices' })
  const next = resourceTabNavigation(query, { cursorHistory: ['previous'] }, '/accounts/B', 'devices', 'networks', 'topology', tabs)
  assert.equal(next.state.resourceTabMemory.views.devices, undefined)
  const returned = resourceTabNavigation(new URLSearchParams(next.search), next.state, '/accounts/B', 'networks', 'devices', 'topology', tabs)
  assert.equal(new URLSearchParams(returned.search).get('cursor'), null)
  assert.deepEqual(returned.state.cursorHistory, [])
})

test('same-page relationship drill-down returns to its filtered index before the external origin', () => {
  const outer = resourceOriginState({ pathname: '/networks', search: '?account_id=B&q=office&network_page=3' })
  const index = { pathname: '/relationships', search: '?account_id=B&q=team&relationship_page=2', state: outer }
  const detail = relationshipDetailNavigation(index, 'shared')
  const back = readRelationshipIndexReturn({ ...index, search: `?${detail.search}`, state: detail.state })
  assert.equal(back.to, '/relationships?account_id=B&q=team&relationship_page=2')
  assert.equal(readResourceReturn(back.state).to, '/networks?account_id=B&q=office&network_page=3')
  assert.equal(back.state.relationshipIndex, undefined)
  assert.equal(relationshipDetailNavigation({ ...index, search: `?${detail.search}`, state: detail.state }, 'shared'), null)
})

test('embedded drill-down does not shadow account return and survives a connection round trip', () => {
  const outer = resourceOriginState({ pathname: '/accounts', search: '?q=alice&cursor=next' })
  const index = { pathname: '/accounts/B', search: '?q=team&relationship_page=2', state: outer }
  const detail = relationshipDetailNavigation(index, 'shared')
  assert.equal(readAccountReturn(detail.state).to, '/accounts?q=alice&cursor=next')
  const connectionState = resourceOriginState({ ...index, search: `?${detail.search}`, state: detail.state })
  const returned = readResourceReturn(connectionState)
  const url = new URL(returned.to, 'https://example.test')
  const back = readRelationshipIndexReturn({ pathname: url.pathname, search: url.search, state: returned.state })
  assert.equal(back.to, '/accounts/B?q=team&relationship_page=2')
})

test('relationship index receipts are bound to path, account and tab and reject external sources', () => {
  const detail = relationshipDetailNavigation({ pathname: '/relationships', search: '?account_id=B' }, 'shared')
  assert.equal(readRelationshipIndexReturn({ pathname: '/relationships', search: '?account_id=C&network_id=shared', state: detail.state }), null)
  assert.equal(readRelationshipIndexReturn({ pathname: '/accounts/B', search: '?account_id=B&network_id=shared', state: detail.state }), null)
  assert.equal(readRelationshipIndexReturn({ pathname: '/relationships', search: '?account_id=B&network_id=shared&tab=devices', state: detail.state }), null)
  assert.equal(readRelationshipIndexReturn({ pathname: '/relationships', search: '?network_id=shared', state: { relationshipIndex: 'https://example.test/relationships' } }), null)
})
