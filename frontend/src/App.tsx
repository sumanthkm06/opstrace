import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import OverviewPage from './pages/OverviewPage'
import HostsPage from './pages/HostsPage'
import ServicesPage from './pages/ServicesPage'
import IncidentsPage from './pages/IncidentsPage'
import IncidentDetailPage from './pages/IncidentDetailPage'
import LogsPage from './pages/LogsPage'
import DependencyPage from './pages/DependencyPage'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/overview" replace />} />
        <Route path="/overview" element={<OverviewPage />} />
        <Route path="/hosts" element={<HostsPage />} />
        <Route path="/services" element={<ServicesPage />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/incidents/:id" element={<IncidentDetailPage />} />
        <Route path="/logs" element={<LogsPage />} />
        <Route path="/dependencies" element={<DependencyPage />} />
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Routes>
    </Layout>
  )
}
