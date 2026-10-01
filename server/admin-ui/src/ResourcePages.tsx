import { type CSSProperties, useEffect, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { ArrowRight, ChevronLeft, Search } from 'lucide-react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { tr } from './i18n'
import { adminApi, ApiError } from './api'
import { accountColor } from './colors'
import { AccountScopePicker } from './AccountScopePicker'
import { SnapshotExport } from './SnapshotExport'
import { CopyValue } from './CopyValue'
import { usePageState, useCursorPage, connectionLink, accountReturnState, readAccountReturn, useResourceTabState, resourceOriginState } from './pageState'
import { QueryStatus, useAutoRefresh } from './refresh'
import { AccountMark, DataTable, Panel, ErrorBlock, PendingBlock, CursorPagination, ResourceTabs, formatAgo, formatDate, useDebouncedValue, ResourceEmptyState, ResourceReturnLink } from './ResourceUI'
import { DeviceTable, NetworkTable, RoomTable } from './ResourceTables'
import { RelationshipsPage } from './ResourceRelationships'
import type { AdminAccount } from './types'
const PAGE_SIZE = 25
export type ResourceAccountScope = { id: string; username: string }

export function AccountsPage() {
  const refreshInterval = useAutoRefresh()
  const location = useLocation()
  const { params, update } = usePageState()
  const paging = useCursorPage()
  const query = params.get('q') || ''
  const debounced = useDebouncedValue(query)
  const result = useQuery({
    queryKey: ['accounts', 'cursor', debounced, paging.cursor],
    queryFn: ({ signal }) => adminApi.accountsSnapshot(debounced, paging.cursor, PAGE_SIZE, signal),
    refetchInterval: refreshInterval,
    enabled: debounced === query,
  })

  const columns = useMemo<ColumnDef<AdminAccount, unknown>[]>(() => [
    { id: 'account', header: '账号', cell: ({ row }) => <div className="identity-cell"><AccountMark account={row.original} /><div><Link className="identity-link" to={`/accounts/${encodeURIComponent(row.original.id)}`} state={accountReturnState(location)}>{row.original.username}</Link><span>{row.original.email}</span></div></div> },
    { id: 'devices', header: '设备', cell: ({ row }) => <div className="ratio-cell"><strong>{row.original.online_devices}{tr("/")}{row.original.device_count}</strong><span>{row.original.device_count ? Math.round(row.original.online_devices / row.original.device_count * 100) : 0}{tr("% 在线")}</span></div> },
    { accessorKey: 'network_count', header: '网络' },
    { accessorKey: 'room_count', header: '房间' },
    { id: 'last_seen', header: '最近活动', cell: ({ row }) => formatAgo(row.original.last_seen) },
    { id: 'created_at', header: '注册时间', cell: ({ row }) => formatDate(row.original.created_at) },
  ], [location])

  return <div className="page-stack">
    <div className="page-intro"><div><h2>{tr("所有账号")}</h2><p>{tr('查看账号的设备、网络和最近活动。')}</p></div><div className="search-field"><Search size={16} /><input value={query} onChange={(event) => update({ q: event.target.value, cursor: '', page: '' }, true)} placeholder={tr("搜索用户名或邮箱")} aria-label={tr("搜索用户名或邮箱")} /></div></div>
    <QueryStatus queries={[result]} />
    <Panel action={result.data && debounced === query && <SnapshotExport items={result.data.items} filename="accounts" total={result.data.total} scope={{ q: query, cursor: paging.cursor }} />}>
      {debounced === query && paging.cursor && result.error instanceof ApiError && result.error.status === 400 && <div className="resource-query-recovery"><button type="button" className="button secondary compact" onClick={() => update({ cursor: '', page: '' }, true)}>{tr('重新从首页加载')}</button></div>}
      {result.isPending || debounced !== query ? <PendingBlock queries={[result]} /> : result.error && !result.data ? <ErrorBlock error={result.error} onRetry={() => { void result.refetch() }} /> : result.data ? <>
        {result.data.items.length ? <DataTable<AdminAccount> columns={columns} data={result.data.items} /> : <ResourceEmptyState message="没有符合条件的账号" onClear={query ? () => update({ q: '', cursor: '', page: '' }) : undefined} />}
        <CursorPagination
          total={result.data.total}
          pageIndex={paging.pageIndex}
          canPrev={paging.canPrev}
          previousIsFirst={paging.previousIsFirst}
          itemCount={result.data.items.length}
          limit={PAGE_SIZE}
          canNext={Boolean(result.data.next_cursor)}
          onPrev={paging.prev}
          onNext={() => paging.next(result.data?.next_cursor || '')}
        />
      </> : <ErrorBlock error={new Error('控制面未返回账号列表。')} />}
    </Panel>
  </div>
}

export function AccountDetailPage() {
  const refreshInterval = useAutoRefresh()
  const { id = '' } = useParams()
  const location = useLocation()
  const origin = readAccountReturn(location.state)
  const { params } = usePageState()
  const tab = ['devices', 'networks', 'rooms'].includes(params.get('tab') || '') ? params.get('tab')! : 'topology'
  const setTab = useResourceTabState(tab, 'topology', ['topology', 'devices', 'networks', 'rooms'])
  useEffect(() => { window.scrollTo(0, 0) }, [id, tab])
  const detail = useQuery({ queryKey: ['account-summary', id], queryFn: ({ signal }) => adminApi.accountSummary(id, signal), enabled: Boolean(id), refetchInterval: refreshInterval })
  const account = detail.data?.account
  return <div className="page-stack">
    <div className="detail-navigation"><Link className="text-link" to={origin.to} state={origin.state}><ChevronLeft size={15} />{tr(origin.label)}</Link><Link state={resourceOriginState(location)} className="button secondary compact" to={connectionLink({ accountId: id })}>{tr('查看账号连接')}<ArrowRight size={15} /></Link></div>
    <QueryStatus queries={[detail]} />
    {detail.isPending ? <PendingBlock queries={[detail]} label="正在加载账号…" /> : detail.error && !account ? <ErrorBlock error={detail.error} onRetry={() => { void detail.refetch() }} /> : account ? <>
      <section className="account-hero">
        <AccountMark account={account} size="large" />
        <div className="account-hero-copy"><span className="account-color-label" style={{ '--account-mark-color': accountColor(account.id) } as CSSProperties}>{tr('ACCOUNT')}</span><h2>{account.username}</h2><p>{account.email}</p><span className="value-with-action"><code>{account.id}</code><CopyValue value={account.id} label="复制账号 ID" /></span></div>
        <div className="account-hero-stats"><div><strong>{account.device_count}</strong><span>{tr('设备')}</span></div><div><strong className="positive-text">{account.online_devices}</strong><span>{tr('在线')}</span></div><div><strong>{account.network_count}</strong><span>{tr('网络')}</span></div><div><strong>{account.room_count}</strong><span>{tr('房间')}</span></div></div>
      </section>
      <ResourceTabs id="account-resources" label="账号资源" value={tab} onChange={setTab} tabs={[
        { value: 'topology', label: tr('关系') }, { value: 'devices', label: `${tr('设备')} ${account.device_count}` }, { value: 'networks', label: `${tr('全部网络')} ${account.network_count}` }, { value: 'rooms', label: `${tr('房间网络')} ${account.room_count}` },
      ]} />
      <div role="tabpanel" id="account-resources-panel" aria-labelledby={`account-resources-${tab}`} tabIndex={0}>
        {tab === 'topology' && <RelationshipsPage accountScope={account} />}
        {tab === 'devices' && <DevicesPage accountScope={account} />}
        {(tab === 'networks' || tab === 'rooms') && <NetworksPage accountScope={account} fixedTab={tab} />}
      </div>
    </> : <ErrorBlock error={new Error('控制面未返回该账号详情，请返回账号列表重试。')} onRetry={() => { void detail.refetch() }} />}
  </div>
}

export function DevicesPage({ accountScope }: { accountScope?: ResourceAccountScope }) {
  const refreshInterval = useAutoRefresh()
  const { params, update } = usePageState()
  const paging = useCursorPage()
  const query = params.get('q') || ''
  const accountId = accountScope?.id || params.get('account_id') || ''
  const account = accountScope || (accountId ? { id: accountId, username: params.get('account_name') || accountId } : null)
  const status = ['online', 'offline'].includes(params.get('status') || '') ? params.get('status')! : 'all'
  const debounced = useDebouncedValue(query)
  const result = useQuery({
    queryKey: ['devices', 'cursor', accountId, debounced, status, paging.cursor],
    queryFn: ({ signal }) => adminApi.devicesSnapshot(debounced, status, paging.cursor, PAGE_SIZE, signal, accountId),
    refetchInterval: refreshInterval, enabled: debounced === query,
  })
  return <div className="page-stack">
    {!accountScope && <ResourceReturnLink />}
    <div className="page-intro"><div><h2>{tr('设备')}</h2><p>{tr(account ? '所选账号下已注册的设备。' : '全部账号下已注册的 P2WLAN 设备。')}</p></div><div className="toolbar-controls">
      <div className="search-field"><Search size={16} /><input value={query} onChange={(event) => update({ q: event.target.value, cursor: '', page: '' }, true)} placeholder={tr('搜索设备、账号、IP 或网络')} aria-label={tr('搜索设备、账号、IP 或网络')} /></div>
      <select className="select-field" value={status} onChange={(event) => update({ status: event.target.value === 'all' ? '' : event.target.value, cursor: '', page: '' })} aria-label={tr('全部状态')}><option value="all">{tr('全部状态')}</option><option value="online">{tr('在线')}</option><option value="offline">{tr('离线')}</option></select>
      {!accountScope && <AccountScopePicker value={account} onChange={(next) => update({ account_id: next?.id || '', account_name: next?.username || '', cursor: '', page: '' })} />}
    </div></div>
    <QueryStatus queries={[result]} />
    <Panel action={result.data && debounced === query && <SnapshotExport items={result.data.items} filename="devices" generatedAt={result.data.generated_at} total={result.data.total} scope={{ q: query, status, account_id: accountId, cursor: paging.cursor }} />}>
      {debounced === query && paging.cursor && result.error instanceof ApiError && result.error.status === 400 && <div className="resource-query-recovery"><button type="button" className="button secondary compact" onClick={() => update({ cursor: '', page: '' }, true)}>{tr('重新从首页加载')}</button></div>}
      {result.isPending || debounced !== query ? <PendingBlock queries={[result]} /> : result.error && !result.data ? <ErrorBlock error={result.error} onRetry={() => { void result.refetch() }} /> : result.data ? <>
        {result.data.items.length ? <DeviceTable devices={result.data.items} accountId={accountId} /> : <ResourceEmptyState message="没有符合条件的设备" onClear={query || status !== 'all' || (!accountScope && accountId) ? () => update({ q: '', status: '', cursor: '', page: '', ...(!accountScope ? { account_id: '', account_name: '' } : {}) }) : undefined} />}
        <CursorPagination total={result.data.total} pageIndex={paging.pageIndex} itemCount={result.data.items.length} limit={PAGE_SIZE} canNext={Boolean(result.data.next_cursor)} canPrev={paging.canPrev} previousIsFirst={paging.previousIsFirst} onPrev={paging.prev} onNext={() => paging.next(result.data?.next_cursor || '')} />
      </> : <ErrorBlock error={new Error('控制面未返回设备列表。')} />}
    </Panel>
  </div>
}

export function NetworksPage({ accountScope, fixedTab }: { accountScope?: ResourceAccountScope; fixedTab?: 'networks' | 'rooms' }) {
  const refreshInterval = useAutoRefresh()
  const { params, update } = usePageState()
  const tab = fixedTab || (params.get('tab') === 'rooms' ? 'rooms' : 'networks')
  const setTab = useResourceTabState(tab, 'networks', ['networks', 'rooms'])
  const query = params.get('q') || ''
  const debounced = useDebouncedValue(query)
  const accountId = accountScope?.id || params.get('account_id') || ''
  const account = accountScope || (accountId ? { id: accountId, username: params.get('account_name') || accountId } : null)
  const paging = useCursorPage()
  const filters = { query: debounced, accountId }
  const networks = useQuery({ queryKey: ['networks', 'snapshot', tab, accountId, debounced, paging.cursor], queryFn: ({ signal }) => adminApi.networksSnapshot(filters, paging.cursor, PAGE_SIZE, signal), enabled: tab === 'networks' && debounced === query, refetchInterval: refreshInterval })
  const rooms = useQuery({ queryKey: ['rooms', 'snapshot', tab, accountId, debounced, paging.cursor], queryFn: ({ signal }) => adminApi.roomsSnapshot(filters, paging.cursor, PAGE_SIZE, signal), enabled: tab === 'rooms' && debounced === query, refetchInterval: refreshInterval })
  const active = tab === 'networks' ? networks : rooms
  return <div className="page-stack">
    {!accountScope && <ResourceReturnLink />}
    <div className="page-intro"><div><h2>{tr(fixedTab ? tab === 'rooms' ? '房间网络' : '全部网络' : '网络与房间')}</h2><p>{tr('全部网络包含普通网络和房间网络，房间网络提供加入状态和房间码。')}</p></div><div className="toolbar-controls">
      <div className="search-field"><Search size={16} /><input value={query} onChange={(event) => update({ q: event.target.value, network_page: '', room_page: '', cursor: '', page: '' }, true)} placeholder={tr('搜索名称、ID、网段或房间码')} aria-label={tr('搜索名称、ID、网段或房间码')} /></div>
      {!accountScope && <AccountScopePicker value={account} onChange={(next) => update({ account_id: next?.id || '', account_name: next?.username || '', network_page: '', room_page: '', cursor: '', page: '' })} />}
    </div></div>
    {!fixedTab && <ResourceTabs id="network-resources" label="网络类型" value={tab} onChange={setTab} tabs={[{ value: 'networks', label: tr('全部网络') }, { value: 'rooms', label: tr('房间网络') }]} />}
    <div {...(!fixedTab ? { role: 'tabpanel', id: 'network-resources-panel', 'aria-labelledby': `network-resources-${tab}`, tabIndex: 0 } : {})}>
      <QueryStatus queries={[active]} />
      <Panel action={debounced === query && tab === 'networks' && networks.data ? <SnapshotExport items={networks.data.items} filename="networks" generatedAt={networks.data.generated_at} total={networks.data.total} scope={{ q: query, account_id: accountId, cursor: paging.cursor }} /> : debounced === query && tab === 'rooms' && rooms.data ? <SnapshotExport items={rooms.data.items} filename="rooms" generatedAt={rooms.data.generated_at} total={rooms.data.total} scope={{ q: query, account_id: accountId, cursor: paging.cursor }} /> : undefined}>
        {debounced === query && paging.cursor && active.error instanceof ApiError && active.error.status === 400 && <div className="resource-query-recovery"><button type="button" className="button secondary compact" onClick={() => update({ cursor: '', page: '' }, true)}>{tr('重新从首页加载')}</button></div>}
        {active.isPending || debounced !== query ? <PendingBlock queries={[active]} /> : active.error && !active.data ? <ErrorBlock error={active.error} onRetry={() => { void active.refetch() }} /> : <>
          {tab === 'networks' && networks.data && (networks.data.items.length ? <NetworkTable networks={networks.data.items} accountId={accountId} /> : <ResourceEmptyState message="没有符合条件的网络" onClear={query || (!accountScope && accountId) ? () => update({ q: '', network_page: '', room_page: '', cursor: '', page: '', ...(!accountScope ? { account_id: '', account_name: '' } : {}) }) : undefined} />)}
          {tab === 'rooms' && rooms.data && (rooms.data.items.length ? <RoomTable rooms={rooms.data.items} accountId={accountId} /> : <ResourceEmptyState message="没有符合条件的房间" onClear={query || (!accountScope && accountId) ? () => update({ q: '', network_page: '', room_page: '', cursor: '', page: '', ...(!accountScope ? { account_id: '', account_name: '' } : {}) }) : undefined} />)}
          {active.data && <CursorPagination total={active.data.total} pageIndex={paging.pageIndex} itemCount={active.data.items.length} limit={PAGE_SIZE} canNext={Boolean(active.data.next_cursor)} canPrev={paging.canPrev} previousIsFirst={paging.previousIsFirst} onPrev={paging.prev} onNext={() => paging.next(active.data?.next_cursor || '')} />}
        </>}
      </Panel>
    </div>
  </div>
}
