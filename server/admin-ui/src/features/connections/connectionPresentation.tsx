import { ArrowDownRight, ChevronRight, CircleAlert } from 'lucide-react'
import { getLocale, tr } from '../../i18n'
import type { AdminConnection } from '../../types'
import { transitionReasonLabel } from './connectionLabels'

export function formatAgo(unix?: number): string {
  if (!unix) return '—'
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - unix)
  const locale = getLocale()
  if (seconds < 45) return tr('刚刚')
  if (seconds < 3600) {
    const count = Math.max(1, Math.floor(seconds / 60))
    return locale === 'zh-CN' ? `${count} 分钟前` : `${count} min ago`
  }
  if (seconds < 86400) {
    const count = Math.floor(seconds / 3600)
    return locale === 'zh-CN' ? `${count} 小时前` : `${count} hr ago`
  }
  if (seconds < 86400 * 30) {
    const count = Math.floor(seconds / 86400)
    return locale === 'zh-CN' ? `${count} 天前` : `${count} days ago`
  }
  return new Intl.DateTimeFormat(locale, { year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(unix * 1000))
}

export function formatDate(unix?: number): string {
  if (!unix) return '—'
  return new Intl.DateTimeFormat(getLocale(), {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(new Date(unix * 1000))
}

export function formatMilliseconds(value?: number): string {
  if (value === undefined) return '—'
  if (value < 1000) return `${value} ms`
  const seconds = Math.round(value / 100) / 10
  if (seconds < 60) return getLocale() === 'zh-CN' ? `${seconds} 秒` : `${seconds} s`
  const minutes = Math.round(seconds / 6) / 10
  return getLocale() === 'zh-CN' ? `${minutes} 分钟` : `${minutes} min`
}

export function pathLabel(path?: string | null): string {
  if (!path) return tr('None')
  if (path === 'direct') return tr('Direct')
  if (path === 'relay') return tr('Relay')
  return tr(path.replaceAll('_', ' '))
}

export function reasonLabel(reason: string): string {
  return transitionReasonLabel(reason, getLocale())
}

export function PathBadge({ connection }: { connection: AdminConnection }) {
  const path = connection.current_path || 'none'
  return <span className={`connection-path-badge ${path} ${connection.fresh ? '' : 'stale'}`}>
    <span />{pathLabel(connection.current_path)}
  </span>
}

export function FreshnessBadge({ connection }: { connection: AdminConnection }) {
  const label = connection.fresh ? tr('Fresh') : connection.freshness === 'reporter_offline' ? tr('Reporter offline') : tr('Stale')
  return <span className={`connection-freshness ${connection.fresh ? 'fresh' : 'stale'}`}>{label}</span>
}

export function ConnectionDirection({ connection }: { connection: AdminConnection }) {
  return <div className="connection-direction-cell">
    <div>
      <strong title={connection.reporting_device_name}>{connection.reporting_device_name}</strong>
      <span>{connection.reporting_username}</span>
    </div>
    <ArrowDownRight size={15} aria-hidden />
    <div>
      <strong title={connection.remote_device_name}>{connection.remote_device_name}</strong>
      <span>{connection.remote_username}</span>
    </div>
  </div>
}

export function ConnectionMobileCard({ connection, onSelect }: {
  connection: AdminConnection
  onSelect: (connection: AdminConnection) => void
}) {
  return <button
    type="button"
    className="connection-mobile-card"
    aria-label={getLocale() === 'zh-CN'
      ? `查看 ${connection.reporting_device_name} 到 ${connection.remote_device_name} 的连接详情`
      : `View connection details from ${connection.reporting_device_name} to ${connection.remote_device_name}`}
    onClick={() => onSelect(connection)}
  >
    <span className="connection-mobile-direction">
      <span><strong>{connection.reporting_device_name}</strong><small>{connection.reporting_username}</small></span>
      <ArrowDownRight size={16} aria-hidden />
      <span><strong>{connection.remote_device_name}</strong><small>{connection.remote_username}</small></span>
    </span>
    <span className="connection-mobile-context">
      <strong>{connection.network_name}</strong>
      <span><PathBadge connection={connection} /><FreshnessBadge connection={connection} /></span>
    </span>
    <span className="connection-mobile-facts">
      <span><small>{tr("验证 RTT")}</small><strong>{connection.last_validation_rtt_ms === undefined ? '—' : `${connection.last_validation_rtt_ms} ms`}</strong></span>
      <span><small>{tr("Path age")}</small><strong>{formatMilliseconds(connection.path_age_ms)}</strong></span>
      <span><small>{tr("最后观测")}</small><strong>{formatAgo(connection.received_at)}</strong></span>
      <span><small>{tr("最近原因")}</small><strong title={connection.transition_reason}>{reasonLabel(connection.transition_reason)}</strong></span>
    </span>
    <ChevronRight className="connection-mobile-chevron" size={16} aria-hidden />
  </button>
}

export function LoadingBlock({ label = '加载中…' }: { label?: string }) {
  return <div className="loading-block"><div className="spinner" />{tr(label)}</div>
}

export function ErrorBlock({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : '加载失败'
  return <div className="error-block"><CircleAlert size={18} /><div><strong>{tr("无法加载数据")}</strong><span>{tr(message)}</span></div></div>
}
