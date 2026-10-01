import type { AdminConnection } from './types'

export const CONNECTION_PAGE_SIZE = 25

export type ConnectionIdentity = Pick<AdminConnection, 'network_id' | 'reporting_device_id' | 'remote_device_id'> &
  Partial<Pick<AdminConnection, 'network_name' | 'reporting_device_name' | 'reporting_username' | 'remote_device_name' | 'remote_username'>>

export function readConnectionSearch(params: URLSearchParams) {
  const rawPage = Number(params.get('page') ?? 1)
  const page = Number.isSafeInteger(rawPage) && rawPage > 0 && Number.isSafeInteger((rawPage - 1) * CONNECTION_PAGE_SIZE) ? rawPage : 1
  const networkId = params.get('network_id') ?? ''
  const selectedNetworkId = params.get('selected_network_id') || networkId
  const reportingDeviceId = params.get('reporting_device_id') ?? ''
  const remoteDeviceId = params.get('remote_device_id') ?? ''
  const path = params.get('path') ?? ''
  const freshness = params.get('freshness') ?? ''
  const legacyTopology = !params.has('tab') && params.get('view') === 'topology'
  const effectiveFreshness = !params.has('freshness') && legacyTopology && params.get('show_stale') !== '1' ? 'fresh' : freshness
  return {
    query: params.get('q') ?? '',
    networkId,
    accountId: params.get('account_id') || params.get('user_id') || '',
    deviceId: params.get('device_id') ?? '',
    path: ['direct', 'relay', 'none'].includes(path) ? path : '',
    freshness: (effectiveFreshness === 'fresh' || effectiveFreshness === 'stale' ? effectiveFreshness : '') as 'fresh' | 'stale' | '',
    view: params.get('tab') === 'topology' || legacyTopology ? 'topology' as const : 'table' as const,
    showStale: effectiveFreshness !== 'fresh',
    page,
    selected: selectedNetworkId && reportingDeviceId && remoteDeviceId ? {
      network_id: selectedNetworkId,
      reporting_device_id: reportingDeviceId,
      remote_device_id: remoteDeviceId,
    } : null,
  }
}

export type ConnectionWorkspaceTab = 'health' | 'all' | 'topology' | 'trends'

export function connectionWorkspaceTab(params: URLSearchParams, pathname = '/connections'): ConnectionWorkspaceTab {
  const tab = params.get('tab')
  if (tab === 'health' || tab === 'all' || tab === 'topology' || tab === 'trends') return tab
  if (pathname === '/health') return 'health'
  return params.get('view') === 'topology' ? 'topology' : 'all'
}

/** One shared scope survives every diagnostic view, including old deep links. */
export function connectionWorkspaceSearch(params: URLSearchParams, tab: ConnectionWorkspaceTab): URLSearchParams {
  const next = new URLSearchParams(params)
  const { freshness } = readConnectionSearch(params)
  next.set('tab', tab)
  if (freshness) next.set('freshness', freshness)
  else next.delete('freshness')
  next.delete('view')
  next.delete('show_stale')
  return next
}

/** Preserve unrelated scope and list state when opening or closing a direction. */
export function updateConnectionSearch(params: URLSearchParams, changes: Record<string, string | null>): URLSearchParams {
  const next = new URLSearchParams(params)
  for (const [key, value] of Object.entries(changes)) {
    if (!value || (key === 'page' && value === '1') || (key === 'view' && value === 'table')) next.delete(key)
    else next.set(key, value)
  }
  return next
}

export function selectConnectionSearch(params: URLSearchParams, connection: ConnectionIdentity | null): URLSearchParams {
  return updateConnectionSearch(params, {
    selected_network_id: connection?.network_id ?? null,
    reporting_device_id: connection?.reporting_device_id ?? null,
    remote_device_id: connection?.remote_device_id ?? null,
    detail: null,
    direction_only: connection && params.get('direction_only') === '1' ? '1' : null,
  })
}

/** An exact-direction filter is valid only in its explicitly selected network. */
export function readDirectionOnlySearch(params: URLSearchParams): ConnectionIdentity | null {
  const { selected, networkId } = readConnectionSearch(params)
  return params.get('direction_only') === '1' && selected?.network_id === networkId ? selected : null
}

/** Explicit recovery from a graph whose filters or bounded page exclude a direction. */
export function isolateConnectionSearch(params: URLSearchParams, connection: ConnectionIdentity): URLSearchParams {
  const next = selectConnectionSearch(connectionWorkspaceSearch(params, 'topology'), connection)
  for (const key of ['q', 'account_id', 'user_id', 'device_id', 'path', 'freshness', 'page', 'alert_page']) next.delete(key)
  next.set('network_id', connection.network_id)
  next.set('direction_only', '1')
  next.set('detail', 'closed')
  return next
}

/** Keep the selected row or graph highlight when dismissing the evidence panel. */
export function closeConnectionDetailSearch(params: URLSearchParams): URLSearchParams {
  return updateConnectionSearch(params, { detail: 'closed' })
}

export function connectionDetailIsOpen(params: URLSearchParams): boolean {
  return params.get('detail') !== 'closed'
}

export function lastAvailableConnectionPage(page: number, total: number): number {
  return Math.min(page, Math.max(1, Math.ceil(total / CONNECTION_PAGE_SIZE)))
}
