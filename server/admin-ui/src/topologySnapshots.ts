import type { AdminTopologySnapshotPage } from './types'

export const TOPOLOGY_NODE_LIMIT = 2000
export const TOPOLOGY_EDGE_LIMIT = 4000
export const TOPOLOGY_PAGE_LIMIT = 64

export function mergeTopologySnapshots(pages: AdminTopologySnapshotPage[]) {
  const first = pages[0]
  if (!first) return undefined
  const nodes = new Map<string, AdminTopologySnapshotPage['nodes'][number]>()
  const edges = new Map<string, AdminTopologySnapshotPage['edges'][number]>()
  let partial = pages.length > TOPOLOGY_PAGE_LIMIT
  let last = first
  for (const page of pages.slice(0, TOPOLOGY_PAGE_LIMIT)) {
    if (page.snapshot_at !== first.snapshot_at || page.scope !== first.scope || page.view !== first.view || page.focus_account_id !== first.focus_account_id) {
      partial = true
      break
    }
    last = page
    for (const node of page.nodes) {
      if (nodes.has(node.id) || nodes.size < TOPOLOGY_NODE_LIMIT) nodes.set(node.id, node)
      else partial = true
    }
    for (const edge of page.edges) {
      if (edges.has(edge.id) || edges.size < TOPOLOGY_EDGE_LIMIT) edges.set(edge.id, edge)
      else partial = true
    }
  }
  partial ||= !last.complete && (nodes.size >= TOPOLOGY_NODE_LIMIT || edges.size >= TOPOLOGY_EDGE_LIMIT || pages.length >= TOPOLOGY_PAGE_LIMIT)
  partial ||= !last.complete && (!last.next_cursor || pages.slice(0, -1).some((page) => page.next_cursor === last.next_cursor))
  return { ...last, nodes: [...nodes.values()], edges: [...edges.values()], partial, complete: last.complete && !partial }
}

export function nextTopologySnapshotCursor(last: AdminTopologySnapshotPage, pages: AdminTopologySnapshotPage[]) {
  if (last.complete || mergeTopologySnapshots(pages)?.partial) return undefined
  // A repeated continuation cannot make progress and must not grow the cache.
  if (pages.slice(0, -1).some((page) => page.next_cursor === last.next_cursor)) return undefined
  return last.next_cursor || undefined
}
