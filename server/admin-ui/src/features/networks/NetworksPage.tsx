import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { AccountScopePicker } from '../../AccountScopePicker'
import { SnapshotExport } from '../../SnapshotExport'
import { ApiError, adminApi } from '../../api'
import { PageHeader } from '../../components/ui/console'
import { tr } from '../../i18n'
import { useCursorPage, usePageState, useResourceTabState } from '../../pageState'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import { CursorPagination, ErrorBlock, Panel, PendingBlock, ResourceEmptyState, ResourceReturnLink, ResourceTabs, useDebouncedValue } from '../../shared/console'
import type { ResourceAccountScope } from '../../types'
import { NetworkTable, RoomTable } from '../resources/ResourceTables'
const PAGE_SIZE = 25

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
    <PageHeader title={tr(fixedTab ? tab === 'rooms' ? '房间网络' : '全部网络' : '网络与房间')} description={<> {tr('全部网络包含普通网络和房间网络，房间网络提供加入状态和房间码。')} </>} actions={<><div className="toolbar-controls">
      <div className="search-field"><Search size={16} /><input value={query} onChange={(event) => update({ q: event.target.value, network_page: '', room_page: '', cursor: '', page: '' }, true)} placeholder={tr('搜索名称、ID、网段或房间码')} aria-label={tr('搜索名称、ID、网段或房间码')} /></div>
      {!accountScope && <AccountScopePicker value={account} onChange={(next) => update({ account_id: next?.id || '', account_name: next?.username || '', network_page: '', room_page: '', cursor: '', page: '' })} />}
    </div></>} />
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
