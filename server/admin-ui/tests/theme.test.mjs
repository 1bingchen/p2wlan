import assert from 'node:assert/strict'
import test from 'node:test'
import vm from 'node:vm'
import { build } from 'esbuild'

const compiled = await build({
  entryPoints: ['src/theme.ts'], bundle: true, write: false, platform: 'node', format: 'cjs',
  plugins: [{ name: 'theme-subscription-harness', setup(builder) {
    builder.onResolve({ filter: /^react$/ }, () => ({ path: 'react', namespace: 'theme-test' }))
    builder.onLoad({ filter: /.*/, namespace: 'theme-test' }, () => ({ contents: 'export const useSyncExternalStore = (subscribe, read) => { globalThis.cleanup.push(subscribe(() => {})); return read() }' }))
  } }],
})

function themeHarness({ initial = null, dark = false, blocked = false } = {}) {
  const events = new Map(), mediaEvents = new Map(), storage = new Map()
  if (initial) storage.set('p2wlan-admin-theme', initial)
  const media = { matches: dark, addEventListener: (key, fn) => mediaEvents.set(key, fn), removeEventListener: (key) => mediaEvents.delete(key) }
  const context = vm.createContext({
    module: { exports: {} }, cleanup: [], document: { documentElement: { dataset: {} } },
    window: { matchMedia: () => media,
      localStorage: { getItem: key => { if (blocked) throw Error('blocked'); return storage.get(key) ?? null }, setItem: (key, value) => { if (blocked) throw Error('blocked'); storage.set(key, value) } },
      addEventListener: (key, fn) => events.set(key, fn), removeEventListener: (key) => events.delete(key),
    },
  })
  vm.runInContext(compiled.outputFiles[0].text, context)
  const api = context.module.exports
  api.useTheme()
  return { api, context, storage, events, mediaEvents, mode: () => context.document.documentElement.dataset,
    system: dark => { media.matches = dark; mediaEvents.get('change')?.() },
    storageChange: value => { storage.set('p2wlan-admin-theme', value); events.get('storage')?.({ key: 'p2wlan-admin-theme', newValue: value }) },
    unmount: () => context.cleanup.splice(0).forEach(fn => fn()),
  }
}

test('system theme follows OS changes while explicit appearance remains stable', () => {
  const h = themeHarness({ dark: true })
  assert.equal(h.api.getTheme(), 'system'); assert.equal(h.mode().theme, 'dark')
  h.system(false); assert.equal(h.mode().theme, 'light')
  h.api.setTheme('dark'); h.system(false); assert.equal(h.mode().theme, 'dark')
  h.api.setTheme('system'); assert.equal(h.mode().theme, 'light')
  h.unmount(); assert.equal(h.events.size, 0); assert.equal(h.mediaEvents.size, 0)
})

test('saved appearance and same-origin storage changes share one theme state', () => {
  const h = themeHarness({ initial: 'light', dark: true })
  assert.equal(h.mode().theme, 'light')
  h.storageChange('dark'); assert.equal(h.api.getTheme(), 'dark'); assert.equal(h.mode().theme, 'dark')
  h.storageChange(null); assert.equal(h.api.getTheme(), 'system')
  h.unmount(); h.storage.set('p2wlan-admin-theme', 'light'); h.api.useTheme()
  assert.equal(h.api.getTheme(), 'light'); assert.equal(h.mode().theme, 'light'); h.unmount()
})

test('blocked storage does not prevent theme changes or reset them on remount', () => {
  const h = themeHarness({ blocked: true })
  h.api.setTheme('dark'); assert.equal(h.mode().theme, 'dark')
  h.unmount(); h.api.useTheme(); assert.equal(h.api.getTheme(), 'dark')
  h.api.setTheme('system'); h.system(true); assert.equal(h.mode().theme, 'dark'); h.unmount()
})
