import { getLocale, tr, useLocale } from './i18n'
import { type FormEvent, type ReactNode, lazy, useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, ArrowRight, CircleAlert, CircleCheck, Eye, EyeOff, KeyRound, LayoutDashboard, Menu, MonitorSmartphone, Network, RadioTower, RefreshCw, Server, ShieldCheck, Users, Waypoints, X } from 'lucide-react'
import { BrowserRouter, Link, NavLink, Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import { adminApi, ApiError, clearAdminToken, getAdminToken, setAdminToken, verifyAdminToken } from './api'
import { AsyncView } from './AsyncView'
import { QueryStatus, useAutoRefresh } from './refresh'
import { ConsolePreferences, LanguageSwitch, ThemeSwitch } from './ConsolePreferences'
import { Dashboard } from './Dashboard'
import { useOverlay } from './useOverlay'
import { ErrorBlock, PendingBlock, Panel, formatDate, formatDuration } from './ResourceUI'
import './dashboard-shell.css'
import { AccountsPage, AccountDetailPage, DevicesPage, NetworksPage } from './ResourcePages'
import { RelationshipsPage } from './ResourceRelationships'
const ConnectionWorkspace = lazy(() => import('./ConnectionWorkspace').then((module) => ({ default: module.ConnectionWorkspace })))

function Login({ onSuccess }: { onSuccess: () => void }) {
  const [token, setToken] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [tokenVisible, setTokenVisible] = useState(false)
  const invalidToken = error === '管理员令牌至少需要 32 个字符。' || error === '管理员令牌无效。'
  const pendingLogin = useRef<AbortController | null>(null)
  useEffect(() => () => {
    const pending = pendingLogin.current
    pendingLogin.current = null
    pending?.abort()
  }, [])

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (pendingLogin.current) return
    const normalized = token.trim()
    if (normalized.length < 32) {
      setError('管理员令牌至少需要 32 个字符。')
      return
    }
    const request = new AbortController()
    pendingLogin.current = request
    const timeout = window.setTimeout(() => request.abort(), 15_000)
    setSubmitting(true)
    setError('')
    try {
      await verifyAdminToken(normalized, request.signal)
      if (pendingLogin.current !== request) return
      if (request.signal.aborted) throw new DOMException('Login timed out', 'AbortError')
      setAdminToken(normalized)
      onSuccess()
    } catch (reason) {
      if (pendingLogin.current !== request) return
      if (request.signal.aborted) setError('验证超时，请检查网络连接后重试。')
      else if (reason instanceof ApiError && reason.status === 401) setError('管理员令牌无效。')
      else if (reason instanceof TypeError) setError('无法连接到控制面，请检查网络连接后重试。')
      else setError(reason instanceof Error ? reason.message : '无法连接到控制面。')
    } finally {
      window.clearTimeout(timeout)
      if (pendingLogin.current === request) {
        pendingLogin.current = null
        setSubmitting(false)
      }
    }
  }

  return <main className="login-page-v2">
    <section className="login-brand-side">
      <div className="brand-lockup large"><div className="brand-symbol"><Waypoints size={22} /></div><div><strong>{tr("P2WLAN")}</strong><span>{tr("Control")}</span></div></div>
      <div className="login-brand-copy"><span className="eyebrow-v2">{tr("SELF-HOSTED CONTROL PLANE")}</span><h1>{tr("资源关系和真实路径，")}<br />{tr("各自说清楚。")}</h1><p>{tr("控制面资源关系与守护进程权威连接观测分开呈现，保持只读运维边界。")}</p></div>
      <div className="login-security"><ShieldCheck size={17} /><span>{tr("管理权限与用户 JWT / 设备凭据完全隔离")}</span></div>
    </section>
    <section className="login-form-side">
      <form className="login-card-v2" onSubmit={submit} aria-busy={submitting}>
        <div className="login-language-row"><span>{tr('界面语言')}</span><div className="login-appearance-controls"><ThemeSwitch /><LanguageSwitch /></div></div>
        <div className="mobile-brand"><div className="brand-symbol"><Waypoints size={20} /></div><strong>{tr("P2WLAN Control")}</strong></div>
        <span className="eyebrow-v2">{tr("ADMIN CONSOLE")}</span>
        <h2>{tr("登录控制台")}</h2>
        <p>{tr("输入部署时配置的 ")}<code>{tr("CONTROL_ADMIN_TOKEN")}</code>{tr("。")}</p>
        <label htmlFor="admin-token">{tr("管理员令牌")}</label>
        <div className="input-with-icon"><KeyRound size={16} /><input id="admin-token" type={tokenVisible ? "text" : "password"} readOnly={submitting} aria-invalid={invalidToken} aria-describedby="admin-token-error" spellCheck={false} value={token} onChange={(event) => { setToken(event.target.value); setError('') }} placeholder={tr("至少 32 个字符")} autoComplete="current-password" autoFocus /><button type="button" className="token-visibility-button" aria-label={tr(tokenVisible ? "隐藏令牌" : "显示令牌")} aria-pressed={tokenVisible} onClick={() => setTokenVisible((value) => !value)}>{tokenVisible ? <EyeOff size={16} /> : <Eye size={16} />}</button></div>
        <div id="admin-token-error" role="status" aria-live="polite" className={`login-error ${error ? 'visible' : ''}`}>{tr(error) || ' '}</div>
        <button className="button primary login-button" type="submit" disabled={submitting}>{submitting ? <><div className="spinner light" />{tr("验证中…")}</> : <>{tr("进入控制台")}<ArrowRight size={16} /></>}</button>
        <div className="session-note"><CircleCheck size={14} />{tr("令牌仅保存在当前标签页会话中")}</div>
      </form>
    </section>
  </main>
}

const navGroups: { label: string; items: { to: string; end?: boolean; icon: ReactNode; label: string }[] }[] = [
  { label: '概览', items: [
    { to: '/', end: true, icon: <LayoutDashboard size={17} />, label: '概览' },
  ] },
  { label: '资源', items: [
    { to: '/accounts', icon: <Users size={17} />, label: '账号' },
    { to: '/devices', icon: <MonitorSmartphone size={17} />, label: '设备' },
    { to: '/networks', icon: <Network size={17} />, label: '网络与房间' },
    { to: '/relationships', icon: <Waypoints size={17} />, label: '资源关系' },
  ] },
  { label: '运维', items: [
    { to: '/connections', icon: <RadioTower size={17} />, label: '连接排障' },
    { to: '/system', icon: <Activity size={17} />, label: '运行状态' },
  ] },
]

function pageMeta(pathname: string): { title: string; eyebrow: string } {
  if (pathname.startsWith('/accounts/')) return { title: '账号详情', eyebrow: 'ACCOUNTS' }
  if (pathname === '/accounts') return { title: '账号', eyebrow: 'ACCOUNTS' }
  if (pathname === '/relationships') return { title: '资源关系', eyebrow: 'RELATIONSHIPS' }
  if (pathname === '/connections' || pathname === '/health') return { title: '连接排障', eyebrow: 'OPERATIONS' }
  if (pathname === '/devices') return { title: '设备', eyebrow: 'DEVICES' }
  if (pathname === '/networks') return { title: '网络与房间', eyebrow: 'NETWORK' }
  if (pathname === '/system') return { title: '运行状态', eyebrow: 'OPERATIONS' }
  return { title: '概览', eyebrow: 'OVERVIEW' }
}

function Shell({ onLogout }: { onLogout: () => void }) {
  const refreshInterval = useAutoRefresh()
  const location = useLocation()
  const meta = pageMeta(location.pathname)
  const queryClient = useQueryClient()
  const runtime = useQuery({ queryKey: ['runtime'], queryFn: ({ signal }) => adminApi.runtime(signal), refetchInterval: refreshInterval })
  const [refreshing, setRefreshing] = useState(false)
  const [navOpen, setNavOpen] = useState(false)
  const navTrigger = useRef<HTMLButtonElement>(null)
  const main = useRef<HTMLElement>(null)
  const previousPath = useRef(location.pathname)
  useOverlay(navOpen, () => { setNavOpen(false); navTrigger.current?.focus() }, { lockScroll: false })

  useEffect(() => {
    window.scrollTo(0, 0)
    setNavOpen(false)
    if (previousPath.current !== location.pathname) main.current?.focus({ preventScroll: true })
    previousPath.current = location.pathname
  }, [location.pathname])

  const refresh = async () => {
    setRefreshing(true)
    try { await queryClient.invalidateQueries() } finally { setRefreshing(false) }
  }
  const runtimeSnapshot = !refreshInterval || runtime.fetchStatus === 'paused' || Boolean(runtime.error)
  const runtimeTime = runtime.dataUpdatedAt ? new Intl.DateTimeFormat(getLocale(), { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(runtime.dataUpdatedAt) : ''

  return <div className="app-layout console-shell">
    <a className="skip-link" href="#main-content">{tr('跳至主内容')}</a>
    <aside className="sidebar-v2" data-mobile-open={navOpen}>
      <div className="console-brand-row">
      <Link to="/" className="brand-lockup"><div className="brand-symbol"><Waypoints size={20} /></div><div><strong>{tr("P2WLAN")}</strong><span>{tr("Control")}</span></div></Link>
      <button ref={navTrigger} type="button" className="icon-button-v2 console-nav-toggle" aria-expanded={navOpen} aria-controls="console-navigation" aria-label={tr(navOpen ? '收起导航' : '展开导航')} onClick={() => setNavOpen((open) => !open)}>{navOpen ? <X size={18} /> : <Menu size={18} />}</button>
      </div>
      <nav id="console-navigation" className="sidebar-nav" aria-label={tr('主导航')}>{navGroups.map((group) => <div className="nav-group" key={group.label}><span className="nav-group-label">{tr(group.label)}</span>{group.items.map((item) => <NavLink key={item.to} to={item.to} end={item.end} onClick={(event) => {
        if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
        setNavOpen(false)
        main.current?.focus({ preventScroll: true })
      }} aria-current={item.to === '/connections' && location.pathname === '/health' ? 'page' : undefined} className={({ isActive }) => `nav-link ${isActive || item.to === '/connections' && location.pathname === '/health' ? 'active' : ''}`}>{item.icon}<span>{tr(item.label)}</span></NavLink>)}</div>)}</nav>
      <div className="sidebar-runtime">
        <div className="runtime-line"><span className={`health-dot${runtimeSnapshot || runtime.isPending ? ' unknown' : ''}`} /><strong>{tr(runtime.fetchStatus === 'paused' ? '控制面状态待更新' : runtime.isError ? '控制面检查失败' : runtime.isPending ? '正在检查控制面' : runtimeSnapshot ? '控制面快照' : '上次检查可达')}</strong></div>
        <span>{runtime.data?.build_version ?? (runtime.isError ? '—' : tr('loading…'))}</span>
        {runtimeTime && <small>{tr('快照截至：')}<time dateTime={new Date(runtime.dataUpdatedAt).toISOString()}>{runtimeTime}</time></small>}
        {!refreshInterval && <small>{tr('自动刷新已关闭，可手动刷新。')}</small>}
        <small>{tr("只读管理模式")}</small>
      </div>
    </aside>
    <div className="app-main">
      <header className="topbar-v2">
        <div className="console-location"><span>{tr(meta.eyebrow)}</span><span aria-hidden>/</span><span>{tr(meta.title)}</span><h1 id="console-page-title" className="sr-only">{tr(meta.title)}</h1></div>
        <div className="topbar-actions-v2">
          <button className="icon-button-v2" disabled={refreshing} onClick={refresh} title={tr("刷新数据")} aria-label={tr("刷新数据")}><RefreshCw size={17} className={refreshing ? 'spin' : ''} /></button>
          {!refreshInterval && <span className="console-paused-label">{tr('自动刷新已关闭。')}</span>}
          <ConsolePreferences onLogout={() => { clearAdminToken(); queryClient.clear(); onLogout() }} />
        </div>
      </header>
      <main ref={main} id="main-content" className="page-content" aria-labelledby="console-page-title" tabIndex={-1}><AsyncView key={location.pathname}><Outlet /></AsyncView></main>
    </div>
  </div>
}

function SystemPage() {
  const refreshInterval = useAutoRefresh()
  const runtime = useQuery({ queryKey: ['runtime'], queryFn: ({ signal }) => adminApi.runtime(signal), refetchInterval: refreshInterval })
  const overview = useQuery({ queryKey: ['overview'], queryFn: ({ signal }) => adminApi.overview(signal), refetchInterval: refreshInterval })
  if (runtime.isPending || overview.isPending) return <PendingBlock queries={[runtime, overview]} />
  const error = runtime.error || overview.error
  if (error && (!overview.data || !runtime.data)) return <ErrorBlock error={error} />
  if (!runtime.data || !overview.data) return <ErrorBlock error={new Error('控制面未返回完整的运行状态快照。')} />
  return <div className="page-stack">
    <QueryStatus queries={[runtime, overview]} />
    <div className="page-intro"><div><h2>{tr("控制面运行健康")}</h2><p>{tr("这里只展示控制面进程与数据库能直接确认的事实；Relay TLS、systemd、SQLite 完整性和备份请在部署主机运行 ")}<code>{tr("p2wlan-server doctor")}</code>{tr("。")}</p></div><span className={`badge ${!refreshInterval || runtime.fetchStatus === 'paused' || runtime.error ? 'warning' : 'success'} large`}><span />{tr(!refreshInterval || runtime.fetchStatus === 'paused' || runtime.error ? '缓存快照' : '运行中')}</span></div>
    <section className="system-grid">
      <Panel title={tr("进程")} subtitle={tr("构建与启动信息")}>
        <div className="system-hero"><div className="system-hero-icon"><Server size={26} /></div><div><span>{tr("UPTIME")}</span><strong>{formatDuration(runtime.data.uptime_seconds)}</strong></div></div>
        <dl className="detail-list">
          <div><dt>{tr("构建版本")}</dt><dd>{runtime.data.build_version}</dd></div>
          <div><dt>{tr("源码提交")}</dt><dd className="mono">{runtime.data.build_commit}</dd></div>
          <div><dt>{tr("启动时间")}</dt><dd>{formatDate(runtime.data.started_at)}</dd></div>
          <div><dt>{tr("管理权限")}</dt><dd>{tr("read-only")}</dd></div>
        </dl>
      </Panel>
      <Panel title={tr("控制面状态")} subtitle={tr("不是业务数据面吞吐")}>
        <div className="system-metrics"><div><span>{tr("待处理信令")}</span><strong>{overview.data.pending_signals}</strong></div><div><span>{tr("活动隧道")}</span><strong>{overview.data.active_tunnels}</strong></div><div><span>{tr("在线设备")}</span><strong>{overview.data.online_devices}</strong></div><div><span>{tr("账号")}</span><strong>{overview.data.users}</strong></div></div>
        <div className="truth-notice system-notice"><CircleAlert size={15} /><span>{tr("控制面正常、设备在线和 Relay RTT 都不能单独证明真实 TUN 或应用流量已端到端可达。主机级部署问题请使用 p2wlan-server doctor 分层检查。")}</span></div>
      </Panel>
    </section>
  </div>
}

function RelationshipAlias() {
  const location = useLocation()
  return <Navigate to={{ pathname: '/relationships', search: location.search }} state={location.state} replace />
}

function AuthenticatedApp({ onLogout }: { onLogout: () => void }) {
  return <BrowserRouter basename="/admin"><Routes>
    <Route element={<Shell onLogout={onLogout} />}>
      <Route index element={<Dashboard />} />
      <Route path="accounts" element={<AccountsPage />} />
      <Route path="accounts/:id" element={<AccountDetailPage />} />
      <Route path="relationships" element={<RelationshipsPage />} />
      <Route path="topology" element={<RelationshipAlias />} />
      <Route path="connections" element={<ConnectionWorkspace />} />
      <Route path="devices" element={<DevicesPage />} />
      <Route path="networks" element={<NetworksPage />} />
      <Route path="health" element={<ConnectionWorkspace />} />
      <Route path="system" element={<SystemPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Route>
  </Routes></BrowserRouter>
}

export default function App() {
  const locale = useLocale()
  const [authenticated, setAuthenticated] = useState(() => Boolean(getAdminToken()))
  const queryClient = useQueryClient()
  useEffect(() => {
    document.documentElement.lang = locale
  }, [locale])
  useEffect(() => {
    const unauthorized = () => {
      // A rejected token must not leave the previous session's pages in the
      // cache, or the next login would briefly render the old session's data.
      queryClient.clear()
      setAuthenticated(false)
    }
    window.addEventListener('p2wlan:unauthorized', unauthorized)
    return () => window.removeEventListener('p2wlan:unauthorized', unauthorized)
  }, [queryClient])
  return authenticated ? <AuthenticatedApp onLogout={() => setAuthenticated(false)} /> : <Login onSuccess={() => setAuthenticated(true)} />
}
