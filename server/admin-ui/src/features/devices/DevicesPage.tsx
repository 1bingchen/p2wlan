import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { AccountScopePicker } from '../../AccountScopePicker'
import { SnapshotExport } from '../../SnapshotExport'
import { ApiError, adminApi } from '../../api'
import { PageHeader } from '../../components/ui/console'
import { tr } from '../../i18n'
import { useCursorPage, usePageState } from '../../pageState'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import { CursorPagination, ErrorBlock, Panel, PendingBlock, ResourceEmptyState, ResourceReturnLink, useDebouncedValue } from '../../shared/console'
import type { ResourceAccountScope } from '../../types'
import { DeviceTable } from '../resources/ResourceTables'
const PAGE_SIZE = 25

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
    <PageHeader title={tr('设备')} description={<> {tr(account ? '所选账号下已注册的设备。' : '全部账号下已注册的 P2WLAN 设备。')} </>} actions={<><div className="toolbar-controls">
      <div className="search-field"><Search size={16} /><input value={query} onChange={(event) => update({ q: event.target.value, cursor: '', page: '' }, true)} placeholder={tr('搜索设备、账号、IP 或网络')} aria-label={tr('搜索设备、账号、IP 或网络')} /></div>
      <select className="select-field" value={status} onChange={(event) => update({ status: event.target.value === 'all' ? '' : event.target.value, cursor: '', page: '' })} aria-label={tr('全部状态')}><option value="all">{tr('全部状态')}</option><option value="online">{tr('在线')}</option><option value="offline">{tr('离线')}</option></select>
      {!accountScope && <AccountScopePicker value={account} onChange={(next) => update({ account_id: next?.id || '', account_name: next?.username || '', cursor: '', page: '' })} />}
    </div></>} />
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
