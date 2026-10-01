import { useSyncExternalStore } from 'react'

export type AdminTheme = 'system' | 'light' | 'dark'
const STORAGE_KEY = 'p2wlan-admin-theme'
const listeners = new Set<() => void>()
const normalize = (value: string | null): AdminTheme => value === 'light' || value === 'dark' ? value : 'system'
const media = typeof window !== 'undefined' && typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-color-scheme: dark)') : undefined

function readInitialTheme(): AdminTheme {
  try { return normalize(window.localStorage.getItem(STORAGE_KEY)) } catch { return 'system' }
}
let activeTheme = readInitialTheme()

function applyTheme() {
  if (typeof document === 'undefined') return
  document.documentElement.dataset.theme = activeTheme === 'system' ? media?.matches ? 'dark' : 'light' : activeTheme
  document.documentElement.dataset.themeMode = activeTheme
}
applyTheme()

function storageChanged(event: StorageEvent) {
  if (event.key !== STORAGE_KEY && event.key !== null) return
  activeTheme = normalize(event.newValue)
  applyTheme()
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void) {
  if (listeners.size === 0) {
    window.addEventListener('storage', storageChanged)
    media?.addEventListener('change', applyTheme)
    // Refresh preferences after a view remount without losing blocked-storage choices.
    try { activeTheme = normalize(window.localStorage.getItem(STORAGE_KEY)) } catch { /* Keep the current page preference. */ }
    applyTheme()
  }
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
    if (listeners.size === 0) {
      window.removeEventListener('storage', storageChanged)
      media?.removeEventListener('change', applyTheme)
    }
  }
}

export function getTheme(): AdminTheme { return activeTheme }
export function setTheme(theme: AdminTheme) {
  if (theme === activeTheme) return
  activeTheme = theme
  try { window.localStorage.setItem(STORAGE_KEY, theme) } catch { /* Keep preferences usable when storage is blocked. */ }
  applyTheme()
  for (const listener of listeners) listener()
}
export function useTheme(): AdminTheme { return useSyncExternalStore(subscribe, getTheme, () => 'system') }
