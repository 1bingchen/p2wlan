import { useEffect, useRef, useState } from 'react'
import { Download } from 'lucide-react'
import { tr } from './i18n'
import './data-actions.css'

const MAX_EXPORT_ITEMS = 1_000

/** Export only the records already loaded in this authenticated page. */
export function SnapshotExport<T>({ items, filename, total, generatedAt, scope = {}, complete }: {
  items: readonly T[]
  filename: string
  total?: number
  generatedAt?: number
  scope?: Record<string, unknown>
  complete?: boolean
}) {
  const [failed, setFailed] = useState(false)
  const pending = useRef<{ url: string; timer: ReturnType<typeof setTimeout> } | null>(null)
  const dispose = () => {
    if (!pending.current) return
    clearTimeout(pending.current.timer)
    URL.revokeObjectURL(pending.current.url)
    pending.current = null
  }
  useEffect(() => dispose, [])
  const download = () => {
    setFailed(false)
    try {
      const selected = items.slice(0, MAX_EXPORT_ITEMS)
      const capped = selected.length < items.length
      const payload = {
        schema_version: 1,
        exported_at: new Date().toISOString(),
        snapshot_generated_at: generatedAt ?? null,
        scope,
        loaded_count: items.length,
        exported_count: selected.length,
        reported_total: total ?? null,
        scope_complete: !capped && (complete ?? (total !== undefined && total === items.length)),
        export_limit: MAX_EXPORT_ITEMS,
        export_truncated: capped,
        items: selected,
      }
      dispose()
      const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' }))
      pending.current = { url, timer: setTimeout(dispose, 5_000) }
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `${filename.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 80) || 'admin-snapshot'}-${Date.now()}.json`
      document.body.appendChild(anchor)
      try { anchor.click() } finally { anchor.remove() }
    } catch {
      dispose()
      setFailed(true)
    }
  }
  return <span className="snapshot-export">
    <button type="button" className="button secondary compact" onClick={download} disabled={!items.length}
      title={tr('仅导出已加载记录，文件包含筛选范围、时间和完整性标记。')}>
      <Download size={14} aria-hidden />{tr('导出已加载记录')}
    </button>
    {failed && <span className="data-action-error" role="alert">{tr('无法导出，请重试。')}</span>}
  </span>
}
