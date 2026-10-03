import { useEffect, useState, lazy } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { getAdminToken } from './api'
import { useLocale } from './i18n'
import { Shell } from './layout/AppShell'
import { LoginPage } from './features/auth/LoginPage'
import { Dashboard } from './features/overview/OverviewPage'
import { AccountsPage } from './features/accounts/AccountsPage'
import { AccountDetailPage } from './features/accounts/AccountDetailPage'
import { DevicesPage } from './features/devices/DevicesPage'
import { NetworksPage } from './features/networks/NetworksPage'
import { RelationshipsPage } from './features/relationships/RelationshipsPage'
import { SystemPage } from './features/system/SystemPage'
const ConnectionWorkspace = lazy(() => import('./features/connections/ConnectionWorkspace').then((module) => ({ default: module.ConnectionWorkspace })))

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
  return authenticated ? <AuthenticatedApp onLogout={() => setAuthenticated(false)} /> : <LoginPage onSuccess={() => setAuthenticated(true)} />
}
