import { useLocation, useNavigate, useSearchParams } from 'react-router-dom'

export function withPageParams(params: URLSearchParams, patch: Record<string, string>) {
  const next = new URLSearchParams(params)
  for (const [key, value] of Object.entries(patch)) {
    if (value) next.set(key, value)
    else next.delete(key)
  }
  return next
}

export function usePageState() {
  const [params, setParams] = useSearchParams()
  const location = useLocation()
  const update = (patch: Record<string, string>, replace = false) => {
    setParams((current) => withPageParams(current, patch), { replace, state: { ...location.state, ...(patch.cursor === '' ? { cursorHistory: [] } : {}) } })
  }
  return { params, update }
}

// Keep a bounded previous-page trail in browser history state, not in a growing URL.
// A shared deep link has no trail; its previous action explicitly returns to page one.
export function useCursorPage() {
  const [params] = useSearchParams()
  const location = useLocation()
  const navigate = useNavigate()
  const cursor = params.get('cursor') || ''
  const parsed = Number(params.get('page'))
  const pageIndex = cursor && Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 0
  const rawHistory: unknown = location.state?.cursorHistory
  const history: string[] = Array.isArray(rawHistory) && rawHistory.every((value) => typeof value === 'string') ? rawHistory.slice(-100) : []
  const move = (nextCursor: string, page: number, trail: string[]) => {
    navigate({ pathname: location.pathname, search: withPageParams(params, { cursor: nextCursor, page: nextCursor ? String(page) : '' }).toString() }, { state: { ...location.state, cursorHistory: trail } })
  }
  return {
    cursor, pageIndex,
    canPrev: Boolean(cursor),
    previousIsFirst: Boolean(cursor) && !history.length,
    next: (nextCursor: string) => { if (nextCursor) move(nextCursor, pageIndex + 1, [...history, cursor].slice(-100)) },
    prev: () => move(history.at(-1) ?? '', Math.max(0, pageIndex - 1), history.slice(0, -1)),
  }
}

export function connectionLink(scope: { deviceId?: string; accountId?: string; networkId?: string }) {
  const params = new URLSearchParams()
  if (scope.deviceId) params.set('device_id', scope.deviceId)
  if (scope.accountId) params.set('account_id', scope.accountId)
  if (scope.networkId) params.set('network_id', scope.networkId)
  return `/connections?${params}`
}

export function relationshipLink(networkId: string, accountId?: string) {
  const params = new URLSearchParams()
  if (networkId === 'default' && accountId) params.set('network_id', `personal:${accountId}`)
  else if (networkId !== 'default') params.set('network_id', networkId)
  if (accountId) params.set('account_id', accountId)
  return `/relationships?${params}`
}

// History state contains only bounded navigation data, never arbitrary nested state.
const RESOURCE_QUERY_KEYS = ['q', 'status', 'cursor', 'page', 'network_page', 'room_page', 'relationship_page', 'network_id', 'resource_q', 'relationship_view', 'topology_view'] as const
const RESOURCE_TABS = ['topology', 'devices', 'networks', 'rooms'] as const
const MAX_ORIGINS = 4
const MAX_QUERY_LENGTH = 8192

type ResourceLocation = { pathname: string; search: string; state?: unknown }
type ViewSnapshot = { query: Record<string, string>; cursorHistory: string[] }
type TabMemory = { owner: string; views: Record<string, ViewSnapshot> }
type ResourceOrigin = { to: string; cursorHistory: string[]; resourceTabMemory?: TabMemory; relationshipIndex?: string }

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function cursorTrail(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  let remaining = 16_384
  const result: string[] = []
  for (const cursor of value.slice(-100).reverse()) {
    if (typeof cursor !== 'string' || cursor.length > remaining) break
    result.unshift(cursor)
    remaining -= cursor.length
  }
  return result
}

function localResourceURL(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > MAX_QUERY_LENGTH || !value.startsWith('/') || value.startsWith('//') || /[\\\u0000-\u001f]/.test(value)) return null
  try {
    const url = new URL(value, 'https://resource-navigation.invalid')
    if (url.origin !== 'https://resource-navigation.invalid' || url.hash || !/^\/(?:accounts(?:\/[^/]+)?|devices|networks|relationships|connections|health)$/.test(url.pathname)) return null
    return url.pathname + url.search
  } catch { return null }
}

function boundedViewQuery(value: unknown): Record<string, string> | undefined {
  const source = record(value)
  const query: Record<string, string> = {}
  let remaining = MAX_QUERY_LENGTH
  for (const key of RESOURCE_QUERY_KEYS) {
    const value = source[key]
    if (value === undefined) continue
    if (typeof value !== 'string' || key.length + value.length > remaining) return undefined
    query[key] = value
    remaining -= key.length + value.length
  }
  return query
}

function readTabMemory(value: unknown): TabMemory | undefined {
  const source = record(value)
  if (typeof source.owner !== 'string' || source.owner.length > 1024) return undefined
  const views: Record<string, ViewSnapshot> = {}
  for (const tab of RESOURCE_TABS) {
    const snapshot = record(record(source.views)[tab])
    const query = boundedViewQuery(snapshot.query)
    if (Object.keys(snapshot).length && query) views[tab] = { query, cursorHistory: query.cursor ? cursorTrail(snapshot.cursorHistory) : [] }
  }
  return { owner: source.owner, views }
}

function readOrigins(state: unknown): ResourceOrigin[] {
  const origins = record(state).resourceOrigins
  if (!Array.isArray(origins)) return []
  return origins.slice(-MAX_ORIGINS).flatMap((item) => {
    const source = record(item)
    const to = localResourceURL(source.to)
    return to ? [{ to, cursorHistory: cursorTrail(source.cursorHistory), resourceTabMemory: readTabMemory(source.resourceTabMemory), relationshipIndex: localResourceURL(source.relationshipIndex) || undefined }] : []
  })
}

export function resourceOriginState(location: ResourceLocation) {
  const to = localResourceURL(location.pathname + location.search)
  const state = record(location.state)
  const origins = readOrigins(state)
  if (to) {
    // Reopening the same source does not create a growing chain of duplicates.
    if (origins.at(-1)?.to === to) origins.pop()
    origins.push({ to, cursorHistory: cursorTrail(state.cursorHistory), resourceTabMemory: readTabMemory(state.resourceTabMemory), relationshipIndex: localResourceURL(state.relationshipIndex) || undefined })
  }
  return { resourceOrigins: origins.slice(-MAX_ORIGINS) }
}

function returnLabel(to: string): string {
  const path = to.split('?')[0]
  if (path.startsWith('/accounts/')) return '返回账号详情'
  if (path === '/accounts') return '返回账号列表'
  if (path === '/devices') return '返回设备列表'
  if (path === '/networks') return '返回网络列表'
  if (path === '/relationships') return '返回资源关系'
  return '返回连接排障'
}

export function readResourceReturn(state: unknown): { to: string; state: unknown; label: string } | null {
  const origins = readOrigins(state)
  const target = origins.pop()
  if (!target) return null
  return { to: target.to, label: returnLabel(target.to), state: { cursorHistory: target.cursorHistory, resourceTabMemory: target.resourceTabMemory, resourceOrigins: origins, relationshipIndex: target.relationshipIndex } }
}

// In-page drill-down belongs to the relationship view, not the outer account's
// return chain. Keep only its bounded URL so the account header still goes back
// to its actual source and a detail's Back first restores its filtered index.
export function relationshipDetailNavigation(location: ResourceLocation, networkId: string) {
  const params = new URLSearchParams(location.search)
  if (!networkId || params.get('network_id') === networkId) return null
  const state = record(location.state)
  const relationshipIndex = params.get('network_id') ? localResourceURL(state.relationshipIndex) : localResourceURL(location.pathname + location.search)
  return { search: withPageParams(params, { network_id: networkId, resource_q: '' }).toString(), state: { ...state, relationshipIndex: relationshipIndex || undefined } }
}

export function readRelationshipIndexReturn(location: ResourceLocation): { to: string; label: string; state: unknown } | null {
  const state = record(location.state)
  const to = localResourceURL(state.relationshipIndex)
  if (!to) return null
  const source = new URL(to, 'https://resource-navigation.invalid')
  const current = new URLSearchParams(location.search)
  if (source.pathname !== location.pathname || source.searchParams.has('network_id') || !current.get('network_id')
    || (source.searchParams.get('account_id') || '') !== (current.get('account_id') || '')
    || (source.searchParams.get('tab') || 'topology') !== (current.get('tab') || 'topology')) return null
  return { to, label: '所有资源', state: { ...state, relationshipIndex: undefined } }
}

export function accountReturnState(location: ResourceLocation) { return resourceOriginState(location) }

export function readAccountReturn(state: unknown): { to: string; state?: unknown; label: string } {
  const current = readResourceReturn(state)
  if (current) return current
  // Old history entries from the previous console retain their safe list return.
  const legacy = record(record(state).accountReturn)
  const to = localResourceURL(legacy.to)
  return to?.split('?')[0] === '/accounts'
    ? { to, label: '返回账号列表', state: { cursorHistory: cursorTrail(record(legacy.state).cursorHistory) } }
    : { to: '/accounts', label: '返回账号列表' }
}

/** Keep each tab's current filters in bounded history state; the active URL stays shareable. */
export function resourceTabNavigation(params: URLSearchParams, rawState: unknown, pathname: string, active: string, nextTab: string, defaultTab: string, allowed: readonly string[]) {
  if (nextTab === active || !allowed.includes(nextTab) || !RESOURCE_TABS.some((tab) => tab === nextTab)) return null
  const state = record(rawState)
  const owner = `${pathname}:${params.get('account_id') || ''}`
  const saved = readTabMemory(state.resourceTabMemory)
  const memory: TabMemory = saved?.owner === owner ? saved : { owner, views: {} }
  const rawQuery: Record<string, string> = {}
  for (const key of RESOURCE_QUERY_KEYS) {
    const value = params.get(key)
    if (value !== null) rawQuery[key] = value
  }
  const query = boundedViewQuery(rawQuery)
  if (RESOURCE_TABS.some((tab) => tab === active)) {
    // Reject the whole over-budget snapshot: a cursor must never outlive its filters.
    if (query) memory.views[active] = { query, cursorHistory: query.cursor ? cursorTrail(state.cursorHistory) : [] }
    else delete memory.views[active]
  }
  const restored = memory.views[nextTab]
  const next = new URLSearchParams(params)
  for (const key of RESOURCE_QUERY_KEYS) next.delete(key)
  for (const [key, value] of Object.entries(restored?.query ?? {})) next.set(key, value)
  if (nextTab === defaultTab) next.delete('tab')
  else next.set('tab', nextTab)
  return { search: next.toString(), state: { ...state, resourceTabMemory: memory, cursorHistory: restored?.cursorHistory ?? [] } }
}

export function useResourceTabState(active: string, defaultTab: string, allowed: readonly string[]) {
  const [params] = useSearchParams()
  const location = useLocation()
  const navigate = useNavigate()
  return (nextTab: string) => {
    const next = resourceTabNavigation(params, location.state, location.pathname, active, nextTab, defaultTab, allowed)
    if (next) navigate({ pathname: location.pathname, search: next.search }, { state: next.state })
  }
}
