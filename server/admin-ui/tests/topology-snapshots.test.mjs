import assert from 'node:assert/strict'
import test from 'node:test'
import { mergeTopologySnapshots, nextTopologySnapshotCursor, TOPOLOGY_NODE_LIMIT, TOPOLOGY_PAGE_LIMIT } from '../src/features/relationships/topologySnapshots.ts'

const page = (values = {}) => ({
  generated_at: 20, snapshot_at: 10, graph_kind: 'control_relationships', scope: 'global', view: 'summary',
  phase: 'accounts', complete: false, next_cursor: 'networks', nodes: [], edges: [], ...values,
})

test('snapshot phases retain relationships until their endpoints are available', () => {
  const pages = [page({ nodes: [{ id: 'account:a' }] }), page({ next_cursor: 'memberships', nodes: [{ id: 'network:n' }] }),
    page({ complete: true, next_cursor: undefined, edges: [{ id: 'membership:a:n', source: 'account:a', target: 'network:n', kind: 'membership' }] })]
  const merged = mergeTopologySnapshots(pages)
  assert.equal(merged.complete, true)
  assert.equal(merged.nodes.length, 2)
  assert.equal(merged.edges.length, 1)
  assert.equal(nextTopologySnapshotCursor(pages.at(-1), pages), undefined)
})

test('mixed snapshot identities never produce a complete or cross-scope graph', () => {
  for (const mismatch of [{ snapshot_at: 11 }, { view: 'full' }, { scope: 'account', focus_account_id: 'other' }]) {
    const pages = [page(), page({ ...mismatch, complete: true, nodes: [{ id: 'foreign' }] })]
    const merged = mergeTopologySnapshots(pages)
    assert.equal(merged.partial, true)
    assert.equal(merged.complete, false)
    assert.equal(merged.nodes.length, 0)
    assert.equal(nextTopologySnapshotCursor(pages.at(-1), pages), undefined)
  }
})

test('large graphs and stalled cursors stop with an explicit incomplete result', () => {
  const oversize = page({ nodes: Array.from({ length: TOPOLOGY_NODE_LIMIT + 1 }, (_, i) => ({ id: String(i) })), complete: true })
  const merged = mergeTopologySnapshots([oversize])
  assert.equal(merged.nodes.length, TOPOLOGY_NODE_LIMIT)
  assert.equal(merged.partial, true)
  assert.equal(merged.complete, false)
  for (const pages of [[page(), page()], [page({ next_cursor: undefined })], Array.from({ length: TOPOLOGY_PAGE_LIMIT }, (_, i) => page({ next_cursor: String(i) }))]) {
    assert.equal(nextTopologySnapshotCursor(pages.at(-1), pages), undefined)
    assert.equal(mergeTopologySnapshots(pages).partial, true)
  }
})
