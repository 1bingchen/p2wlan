import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { Search } from 'lucide-react'
import { useMemo } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { SnapshotExport } from '../../SnapshotExport'
import { ApiError, adminApi } from '../../api'
import { PageHeader } from '../../components/ui/console'
import { tr } from '../../i18n'
import { accountReturnState, useCursorPage, usePageState } from '../../pageState'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import { AccountMark, CursorPagination, DataTable, ErrorBlock, Panel, PendingBlock, ResourceEmptyState, formatAgo, formatDate, useDebouncedValue } from '../../shared/console'
import type { AdminAccount } from '../../types'
const PAGE_SIZE = 25

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
    <PageHeader title={tr("所有账号")} description={<> {tr('查看账号的设备、网络和最近活动。')} </>} actions={<><div className="search-field"><Search size={16} /><input value={query} onChange={(event) => update({ q: event.target.value, cursor: '', page: '' }, true)} placeholder={tr("搜索用户名或邮箱")} aria-label={tr("搜索用户名或邮箱")} /></div></>} />
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
