import { useQuery } from '@tanstack/react-query'
import { ArrowRight, ChevronRight, CircleAlert, CircleCheck, MonitorSmartphone, RadioTower } from 'lucide-react'
import { Link } from 'react-router-dom'
import { adminApi } from '../../api'
import { PageHeader } from '../../components/ui/console'
import { getLocale, tr } from '../../i18n'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import { AccountMark, ErrorBlock, Panel, PendingBlock, formatAgo } from '../../shared/console'
import type { AdminConnectionHealthAlert } from '../../types'
import { healthSignalLabel } from '../connections/connectionLabels'
import { selectConnectionSearch } from '../connections/connectionNavigation'

function AttentionRow({ alert }: { alert: AdminConnectionHealthAlert }) {
  const search = selectConnectionSearch(new URLSearchParams('tab=health'), alert)
  return <Link className="dashboard-alert-row" to={`/connections?${search}`}>
    <CircleAlert size={17} className={alert.severity === 'warning' ? 'dashboard-alert-warning' : ''} aria-hidden />
    <span className="dashboard-alert-main"><strong>{alert.reporting_device_name || alert.reporting_device_id} → {alert.remote_device_name || alert.remote_device_id}</strong>
      <span>{alert.signals.map((signal) => healthSignalLabel(signal, getLocale())).join(' · ')}</span></span>
    <span className="dashboard-alert-context"><strong>{alert.network_name || alert.network_id}</strong><span>{tr('最近证据')} · {formatAgo(Math.max(alert.received_at, alert.last_transition_at || 0))}</span></span>
    <ChevronRight size={16} aria-hidden />
  </Link>
}

export function Dashboard() {
  const refetchInterval = useAutoRefresh()
  const overview = useQuery({ queryKey: ['overview'], queryFn: ({ signal }) => adminApi.overview(signal), refetchInterval })
  const accounts = useQuery({ queryKey: ['accounts', 'recent'], queryFn: () => adminApi.accounts('', 6, 0), refetchInterval })
  const health = useQuery({ queryKey: ['connection-health', 'dashboard', 3600], queryFn: ({ signal }) => adminApi.connectionHealth({ windowSeconds: 3600 }, 5, signal), refetchInterval })
  const offlineDevices = overview.data ? Math.max(0, overview.data.devices - overview.data.online_devices) : 0
  const healthSnapshot = !refetchInterval || health.isError || health.fetchStatus !== 'idle'
  const overviewSnapshot = !refetchInterval || overview.isError || overview.fetchStatus !== 'idle'
  const accountsSnapshot = !refetchInterval || accounts.isError || accounts.fetchStatus !== 'idle'
  return <div className="page-stack dashboard-page">
    <PageHeader title={tr('运维概览')} description={<> {tr('全部账号 · 先查看需要关注的连接，再浏览资源。')} </>} />
    <section className="dashboard-section" aria-label={tr('连接待关注')}>
      <QueryStatus queries={[health]} label="连接观测" />
      <Panel title={tr('需要关注')} subtitle={tr('最近 1 小时 · 依据端点上报与路径迁移记录')} action={<Link className="text-link" to="/connections?tab=health">{tr('查看全部提醒')}{health.data && <span>({health.data.alerts_total})</span>}<ArrowRight size={14} /></Link>}>
        {health.isPending ? <PendingBlock queries={[health]} label="正在读取连接提醒…" /> : health.error && !health.data ? <ErrorBlock error={health.error} onRetry={() => { void health.refetch() }} /> : health.data && <>
          {health.data.alerts.length ? <div>{health.data.alerts.map((alert) => <AttentionRow key={`${alert.network_id}:${alert.reporting_device_id}:${alert.remote_device_id}`} alert={alert} />)}</div> : <div className="dashboard-empty">
            {health.data.summary.total_observations === 0 ? <MonitorSmartphone size={22} aria-hidden /> : <CircleCheck size={22} aria-hidden />}<div><strong>{tr(healthSnapshot ? health.data.summary.total_observations === 0 ? '上次快照中没有连接观测' : '上次快照中没有待关注提醒' : health.data.summary.total_observations === 0 ? '尚无连接观测' : '当前范围没有待关注提醒')}</strong><p>{tr(health.data.summary.total_observations === 0 ? '端点上报连接后，才会在这里生成提醒。可先查看已注册设备。' : '这表示当前记录未触发提醒，不代表所有业务已经验证可达。')}</p><Link className="text-link" to={health.data.summary.total_observations === 0 ? '/devices' : '/connections?tab=all'}>{tr(health.data.summary.total_observations === 0 ? '查看设备' : '查看全部观测')}<ArrowRight size={14} /></Link></div>
          </div>}
          {health.data.alerts_total > health.data.alerts.length && <div className="dashboard-preview-note">{tr('这里只显示优先级最高的前 5 条提醒；完整列表请查看全部提醒。')}</div>}
          <div className="dashboard-evidence-summary"><span>{tr('Fresh Direct')} <strong>{health.data.summary.fresh_direct}</strong></span><span>{tr('Fresh Relay')} <strong>{health.data.summary.fresh_relay}</strong></span><span>{tr('Path switches')} <strong>{health.data.summary.recent_path_switches}</strong></span><span>{tr('提醒保持方向性，不推断双向业务可达。')}</span></div>
        </>}
      </Panel>
    </section>
    <section className="dashboard-section" aria-label={tr('资源快照')}>
      <QueryStatus queries={[overview]} label="资源快照" />
      {overview.isPending ? <PendingBlock queries={[overview]} label="正在读取控制面状态…" /> : overview.error && !overview.data ? <ErrorBlock error={overview.error} onRetry={() => { void overview.refetch() }} /> : overview.data && <>
        <div className="dashboard-resource-strip">
          <Link to="/accounts"><span>{tr('账号')}</span><strong>{overview.data.users}</strong></Link>
          <Link to="/devices"><span>{tr('设备在线 / 总数')}</span><strong>{overview.data.online_devices}/{overview.data.devices}</strong><small>{tr(overviewSnapshot ? '上次资源快照' : overview.data.devices === 0 ? '尚无设备' : offlineDevices ? '存在离线设备' : '当前记录均在线')}</small></Link>
          <Link to="/networks"><span>{tr('网络')}</span><strong>{overview.data.networks}</strong><small>{overview.data.rooms} {tr('个房间网络')}</small></Link>
          <Link to="/system"><span>{tr('待处理信令')}</span><strong>{overview.data.pending_signals}</strong><small>{tr('控制面协调消息')}</small></Link>
        </div>
        {overview.data.devices === 0 ? <div className="dashboard-resource-note"><MonitorSmartphone size={18} aria-hidden /><span>{tr(overviewSnapshot ? '上次资源快照中没有设备，请刷新后确认。' : '尚未注册设备。注册并连接客户端后，这里会显示资源与在线状态。')}</span><Link to="/devices" className="text-link">{tr('查看设备')}<ArrowRight size={14} /></Link></div> : offlineDevices > 0 && <div className="dashboard-resource-note"><MonitorSmartphone size={18} aria-hidden /><span>{offlineDevices} {tr('台设备在当前快照中离线；离线本身不等同于故障。')}</span><Link to="/devices?status=offline" className="text-link">{tr('查看离线设备')}<ArrowRight size={14} /></Link></div>}
        {overview.data.pending_signals > 0 && <div className="dashboard-resource-note"><RadioTower size={18} aria-hidden /><span>{tr('待处理信令用于连接协调，数量非零不等同于路径故障。')}</span></div>}
      </>}
    </section>
    <section className="dashboard-section" aria-label={tr('最近账号')}>
      <QueryStatus queries={[accounts]} label="最近账号" />
      <Panel title={tr('最近账号')} subtitle={tr('按设备最后活动时间排序')} action={<Link className="text-link" to="/accounts">{tr('全部账号')}<ArrowRight size={14} /></Link>}>
        <div className="recent-account-list">{accounts.isPending ? <PendingBlock queries={[accounts]} /> : accounts.error && !accounts.data ? <ErrorBlock error={accounts.error} onRetry={() => { void accounts.refetch() }} /> : <>
          {accounts.data?.items.length === 0 && <div className="table-empty">{tr(accountsSnapshot ? '上次快照中没有账号' : '暂无账号')}</div>}
          {accounts.data?.items.map((account) => <Link className="recent-account-row" to={`/accounts/${encodeURIComponent(account.id)}`} key={account.id}><AccountMark account={account} /><div className="recent-account-main"><strong>{account.username}</strong><span>{account.email}</span></div><div className="recent-account-stat"><strong>{account.online_devices}/{account.device_count}</strong><span>{tr('在线设备')}</span></div><div className="recent-account-stat"><strong>{account.network_count}</strong><span>{tr('网络')}</span></div><div className="recent-account-time">{formatAgo(account.last_seen)}</div><ChevronRight size={15} /></Link>)}
        </>}</div>
      </Panel>
    </section>
  </div>
}
