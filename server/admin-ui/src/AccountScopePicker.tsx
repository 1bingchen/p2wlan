import { useEffect, useId, useLayoutEffect, useRef, useState, type CSSProperties } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Check, ChevronDown, ChevronLeft, ChevronRight, Search, X } from 'lucide-react'
import { adminApi, ApiError } from './api'
import { tr } from './i18n'
import type { AdminAccount } from './types'
import { useOverlay } from './useOverlay'

type AccountScope = Pick<AdminAccount, 'id' | 'username'>
const PAGE_SIZE = 25

export function AccountScopePicker({ value, onChange }: {
  value: AccountScope | null
  onChange: (value: AccountScope | null) => void
}) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [cursors, setCursors] = useState([''])
  const rootRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const panelId = useId()
  const selectedLabel = value ? `${value.username} · ${value.id}` : tr('全部账号')
  useOverlay(open, () => { setOpen(false); triggerRef.current?.focus() }, { lockScroll: false })

  useEffect(() => {
    if (search.trim() === query) return
    const timeout = window.setTimeout(() => { setQuery(search.trim()); setCursors(['']) }, 250)
    return () => window.clearTimeout(timeout)
  }, [search, query])

  useEffect(() => {
    if (!open) return
    const outside = (event: PointerEvent) => {
      if (event.target instanceof Node && !rootRef.current?.contains(event.target)) setOpen(false)
    }
    document.addEventListener('pointerdown', outside)
    return () => {
      document.removeEventListener('pointerdown', outside)
    }
  }, [open])

  const choose = (account: AccountScope | null) => {
    onChange(account)
    setOpen(false)
    triggerRef.current?.focus()
  }

  return <div className="account-scope-picker" ref={rootRef} onBlur={(event) => {
    if (event.relatedTarget && !event.currentTarget.contains(event.relatedTarget)) setOpen(false)
  }}>
    <div className="account-scope-control">
      <button ref={triggerRef} type="button" className="select-field account-scope-trigger" title={selectedLabel} aria-label={`${tr('筛选账号')}: ${selectedLabel}`} aria-expanded={open} aria-controls={panelId} aria-haspopup="dialog" onClick={() => setOpen((current) => !current)}>
        <span>{value ? <><strong>{value.username}</strong><small>{value.id}</small></> : tr('全部账号')}</span><ChevronDown size={15} />
      </button>
      {value && <button type="button" className="icon-button-v2 account-scope-clear" title={tr('清除账号范围')} aria-label={tr('清除账号范围')} onClick={() => choose(null)}><X size={15} /></button>}
    </div>
    {open && <AccountScopePanel panelId={panelId} value={value} search={search} query={query} cursors={cursors}
      onSearch={setSearch} onCursors={setCursors} onChoose={choose} onClose={() => { setOpen(false); triggerRef.current?.focus() }} />}
  </div>
}

// Mounting the request owner only while open lets Query remove its last observer
// and abort the consumed signal on close, without cancelling another picker.
function AccountScopePanel({ panelId, value, search, query, cursors, onSearch, onCursors, onChoose, onClose }: {
  panelId: string
  value: AccountScope | null
  search: string
  query: string
  cursors: string[]
  onSearch: (value: string) => void
  onCursors: (value: string[]) => void
  onChoose: (value: AccountScope | null) => void
  onClose: () => void
}) {
  const panelRef = useRef<HTMLElement>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const [placement, setPlacement] = useState<CSSProperties>({ visibility: 'hidden' })
  useLayoutEffect(() => {
    const position = () => {
      const anchor = panelRef.current?.parentElement?.querySelector('.account-scope-control')
      if (!anchor) return
      const rect = anchor.getBoundingClientRect()
      const viewport = window.visualViewport
      const width = viewport?.width ?? window.innerWidth
      const height = viewport?.height ?? window.innerHeight
      const left = viewport?.offsetLeft ?? 0
      const top = viewport?.offsetTop ?? 0
      const margin = Math.min(12, width / 4, height / 4)
      const panelWidth = Math.min(340, width - margin * 2)
      const availableHeight = height - margin * 2
      const visibleTop = top + margin
      const visibleBottom = top + height - margin
      const belowTop = Math.max(visibleTop, Math.min(rect.bottom + 8, visibleBottom))
      const aboveBottom = Math.max(visibleTop, Math.min(rect.top - 8, visibleBottom))
      const below = visibleBottom - belowTop
      const above = aboveBottom - visibleTop
      const useAbove = below < 320 && above > below
      const room = useAbove ? above : below
      const fullViewport = room < 200
      const next: CSSProperties = {
        left: Math.max(left + margin, Math.min(rect.right - panelWidth, left + width - margin - panelWidth)),
        width: panelWidth,
        maxHeight: fullViewport ? availableHeight : Math.min(room, availableHeight),
        top: fullViewport ? visibleTop : useAbove ? undefined : belowTop,
        bottom: !fullViewport && useAbove ? window.innerHeight - aboveBottom : undefined,
      }
      setPlacement((previous) => Object.keys(next).every((key) => previous[key as keyof CSSProperties] === next[key as keyof CSSProperties]) ? previous : next)
    }
    position()
    window.addEventListener('resize', position)
    window.addEventListener('scroll', position, true)
    window.visualViewport?.addEventListener('resize', position)
    window.visualViewport?.addEventListener('scroll', position)
    return () => {
      window.removeEventListener('resize', position)
      window.removeEventListener('scroll', position, true)
      window.visualViewport?.removeEventListener('resize', position)
      window.visualViewport?.removeEventListener('scroll', position)
    }
  }, [])
  useEffect(() => { searchRef.current?.focus() }, [])
  const cursor = cursors[cursors.length - 1]
  const searching = search.trim() !== query
  const result = useQuery({
    queryKey: ['accounts', 'scope-picker', query, cursor],
    queryFn: ({ signal }) => adminApi.accountsCursor(query, cursor, PAGE_SIZE, signal),
    enabled: !searching,
    refetchOnMount: 'always',
    gcTime: 60_000,
  })
  const retained = Boolean(result.data && (result.isFetching || result.isError || result.fetchStatus === 'paused'))
  const queryRejected = Boolean(cursor && result.error instanceof ApiError && result.error.status === 400)
  const retry = <button type="button" className="button secondary compact" disabled={result.isFetching || result.fetchStatus === 'paused'} onClick={() => { void result.refetch() }}>{tr('重试')}</button>
  return <section ref={panelRef} id={panelId} className="account-scope-panel" style={placement} role="dialog" aria-label={tr('账号筛选')}>
    <header><strong>{tr('筛选账号')}</strong><button type="button" className="icon-button-v2" aria-label={tr('关闭账号筛选')} onClick={onClose}><X size={15} /></button></header>
    <div className="search-field"><Search size={15} /><input ref={searchRef} aria-label={tr('搜索账号')} placeholder={tr('搜索用户名或邮箱')} value={search} onChange={(event) => onSearch(event.target.value)} /></div>
    <button type="button" className="account-scope-option" aria-pressed={!value} onClick={() => onChoose(null)}><span>{tr('全部账号')}</span>{!value && <Check size={15} />}</button>
    <div className="account-scope-results" aria-busy={result.isFetching || searching}>
      {searching ? <p role="status">{tr('加载中…')}</p> : <>
        {retained && <div className="account-scope-notice" role="status"><p>{tr(result.fetchStatus === 'paused' ? '当前离线，以下为缓存账号列表。' : result.isError ? '账号列表更新失败，以下为缓存结果。' : '正在更新账号列表，以下为上次读取的结果。')}</p>{result.isError && retry}</div>}
        {!result.data ? result.fetchStatus === 'paused' ? <p role="alert">{tr('浏览器当前离线，无法访问控制面。网络恢复后会自动重新请求。')}</p> : result.isError ? <div role="alert"><p>{tr('无法加载数据')}</p>{retry}</div> : <p role="status">{tr('加载中…')}</p> : <>
          {result.data.items.map((account) => <button type="button" className="account-scope-option" key={account.id} title={`${account.username} · ${account.email} · ${account.id}`} aria-pressed={value?.id === account.id} onClick={() => onChoose(account)}><span><strong>{account.username}</strong><small>{account.email}</small><small className="account-scope-id">{account.id}</small></span>{value?.id === account.id && <Check size={15} />}</button>)}
          {result.data.items.length === 0 && <p role="status">{tr(retained ? '上次读取的列表为空。' : '没有符合条件的账号')}</p>}
        </>}
        {queryRejected && <button type="button" className="button secondary compact" onClick={() => onCursors([''])}>{tr('重新从首页加载')}</button>}
      </>}
    </div>
    <footer>
      <button type="button" className="button secondary compact" disabled={!cursor || result.isFetching || searching} onClick={() => onCursors(cursors.length > 1 ? cursors.slice(0, -1) : [''])}><ChevronLeft size={14} />{tr(cursors.length === 1 && cursor ? '返回首页' : '上一页')}</button>
      <span className="account-scope-count">{result.data && !searching ? <>{retained && <strong>{tr('缓存结果')} · </strong>}{tr('本页 ')}{result.data.items.length}{tr(' 条 · 共 ')}{result.data.total}{tr(' 条')}</> : '—'}</span>
      <button type="button" className="button secondary compact" disabled={!result.data?.next_cursor || result.isFetching || searching || result.isError || result.fetchStatus === 'paused'} onClick={() => { if (result.data?.next_cursor) onCursors([...cursors, result.data.next_cursor].slice(-100)) }}>{tr('下一页')}<ChevronRight size={14} /></button>
    </footer>
  </section>
}
