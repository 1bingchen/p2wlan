import { useSyncExternalStore } from 'react'
import { tr } from './i18n'

type Density = 'standard' | 'compact'
const KEY = 'p2wlan-admin-density'
const listeners = new Set<() => void>()
function storedDensity(): Density {
  try { return localStorage.getItem(KEY) === 'compact' ? 'compact' : 'standard' } catch { return 'standard' }
}
let density: Density = typeof window === 'undefined' ? 'standard' : storedDensity()
function apply(next: Density) {
  density = next
  if (typeof document !== 'undefined') document.documentElement.dataset.density = next
  for (const listener of listeners) listener()
}
apply(density)
function subscribe(listener: () => void) {
  listeners.add(listener)
  const storage = (event: StorageEvent) => {
    if (event.key !== KEY && event.key !== null) return
    const next = event.newValue === 'compact' ? 'compact' : 'standard'
    if (next !== density) apply(next)
  }
  window.addEventListener('storage', storage)
  return () => { listeners.delete(listener); window.removeEventListener('storage', storage) }
}
export function DensityToggle() {
  const current = useSyncExternalStore(subscribe, () => density, () => 'standard')
  return <label className="density-control"><span>{tr('密度')}</span><select aria-label={tr('表格密度')} value={current} onChange={(event) => {
    const next = event.target.value === 'compact' ? 'compact' : 'standard'
    try { localStorage.setItem(KEY, next) } catch { /* The current tab can still change density. */ }
    apply(next)
  }}><option value="standard">{tr('标准')}</option><option value="compact">{tr('紧凑')}</option></select></label>
}
