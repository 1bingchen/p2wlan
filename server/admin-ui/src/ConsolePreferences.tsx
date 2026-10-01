import { type ReactNode, useEffect, useId, useRef, useState } from 'react'
import { LogOut, Moon, Settings2, Sun, X } from 'lucide-react'
import { setLocale, tr, useLocale } from './i18n'
import { setTheme, useTheme } from './theme'
import { DensityToggle } from './density'
import { RefreshToggle } from './refresh'
import { useOverlay } from './useOverlay'

export function LanguageSwitch() {
  const locale = useLocale()
  return <div className="locale-switch" role="group" aria-label={tr('界面语言')}>
    <button type="button" className={locale === 'zh-CN' ? 'active' : ''} aria-pressed={locale === 'zh-CN'} title={tr('简体中文')} onClick={() => setLocale('zh-CN')}>中</button>
    <button type="button" className={locale === 'en-US' ? 'active' : ''} aria-pressed={locale === 'en-US'} title="English" onClick={() => setLocale('en-US')}>EN</button>
  </div>
}

export function ThemeSwitch() {
  const theme = useTheme()
  const label = tr(theme === 'dark' ? '切换到浅色主题' : '切换到深色主题')
  return <button type="button" className="theme-switch" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} title={label} aria-label={label}>
    {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
  </button>
}

function PreferenceRow({ label, children }: { label: string; children: ReactNode }) {
  return <div className="console-preference-row"><span>{tr(label)}</span>{children}</div>
}

export function ConsolePreferences({ onLogout }: { onLogout: () => void }) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const trigger = useRef<HTMLButtonElement>(null)
  const closeButton = useRef<HTMLButtonElement>(null)
  const panelId = useId()
  const close = () => { setOpen(false); trigger.current?.focus() }
  useOverlay(open, close, { lockScroll: false })
  useEffect(() => {
    if (!open) return
    closeButton.current?.focus()
    const outside = (event: PointerEvent) => {
      if (event.target instanceof Node && !root.current?.contains(event.target)) setOpen(false)
    }
    document.addEventListener('pointerdown', outside)
    return () => document.removeEventListener('pointerdown', outside)
  }, [open])
  return <div className="console-preferences" ref={root} onBlur={(event) => {
    if (event.relatedTarget && !event.currentTarget.contains(event.relatedTarget)) setOpen(false)
  }}>
    <button ref={trigger} type="button" className="icon-button-v2" title={tr('控制台偏好')} aria-label={tr('控制台偏好')} aria-expanded={open} aria-controls={panelId} aria-haspopup="dialog" onClick={() => setOpen((value) => !value)}><Settings2 size={17} /></button>
    {open && <section id={panelId} className="console-preferences-panel" role="dialog" aria-label={tr('控制台偏好')}>
      <header><strong>{tr('控制台偏好')}</strong><button ref={closeButton} type="button" className="icon-button-v2" aria-label={tr('关闭偏好')} onClick={close}><X size={16} /></button></header>
      <RefreshToggle />
      <PreferenceRow label="界面主题"><ThemeSwitch /></PreferenceRow>
      <PreferenceRow label="界面语言"><LanguageSwitch /></PreferenceRow>
      <div className="console-preference-row"><DensityToggle /></div>
      <footer><span>{tr('只读管理模式')}</span><button type="button" className="button secondary compact" onClick={onLogout}><LogOut size={15} />{tr('退出登录')}</button></footer>
    </section>}
  </div>
}
