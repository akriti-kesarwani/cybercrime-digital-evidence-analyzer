import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import ProtectedRoute from './components/layout/ProtectedRoute'
import AppLayout from './components/layout/AppLayout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Cases from './pages/Cases'
import NewCase from './pages/NewCase'
import CaseDetail from './pages/CaseDetail'
import EvidencePage from './pages/EvidencePage'
import Timeline from './pages/Timeline'
import Alerts from './pages/Alerts'
import Indicators from './pages/Indicators'
import Report from './pages/Report'
import AuditLogs from './pages/AuditLogs'
import Profile from './pages/Profile'
import Settings from './pages/Settings'

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />

          <Route
            element={
              <ProtectedRoute>
                <AppLayout />
              </ProtectedRoute>
            }
          >
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/cases" element={<Cases />} />
            <Route path="/cases/new" element={<NewCase />} />
            <Route path="/cases/:id/*" element={<CaseDetail />} />
            <Route path="/evidence" element={<EvidencePage />} />
            <Route path="/timeline" element={<Timeline />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/indicators" element={<Indicators />} />
            <Route path="/reports" element={<Report />} />
            <Route path="/audit-logs" element={<AuditLogs />} />
            <Route path="/profile" element={<Profile />} />
            <Route path="/settings" element={<Settings />} />
          </Route>

          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
