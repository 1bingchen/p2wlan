import { useQuery } from '@tanstack/react-query'
import { ArrowRight, ChevronLeft } from 'lucide-react'
import { type CSSProperties, useEffect } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { CopyValue } from '../../CopyValue'
import { adminApi } from '../../api'
import { accountColor } from '../../colors'
import { tr } from '../../i18n'
import { connectionLink, readAccountReturn, resourceOriginState, usePageState, useResourceTabState } from '../../pageState'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import { AccountMark, ErrorBlock, PendingBlock, ResourceTabs } from '../../shared/console'
import { DevicesPage } from '../devices/DevicesPage'
import { NetworksPage } from '../networks/NetworksPage'
import { RelationshipsPage } from '../relationships/RelationshipsPage'

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
