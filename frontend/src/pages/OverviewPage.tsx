import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { hostsApi, servicesApi, incidentsApi } from '../services/api'
import type { Host, Service, Incident } from '../types'
import { LoadingState, ErrorState } from '../components/States'
import { SeverityBadge, StatusBadge, IncidentStatusBadge } from '../components/Badges'

function fmt(bytes: number | null): string {
  if (!bytes) return '—'
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`
  return `${(bytes / 1e6).toFixed(0)} MB`
}

function StatCard({ label, value, sub, accent }: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className="card">
      <div className="card-title">{label}</div>
      <div className="stat-value" style={accent ? { color: accent } : undefined}>{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}

export default function OverviewPage() {
  const [hosts, setHosts] = useState<Host[] | null>(null)
  const [services, setServices] = useState<Service[] | null>(null)
  const [incidents, setIncidents] = useState<Incident[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([
      hostsApi.list(),
      servicesApi.list(),
      incidentsApi.list(),
    ]).then(([h, s, i]) => {
      setHosts(h)
      setServices(s)
      setIncidents(i)
    }).catch(e => setError(e.message))
  }, [])

  if (error) return <ErrorState message={`Failed to load overview: ${error}`} />
  if (!hosts || !services || !incidents) return <LoadingState message="Loading overview…" />

  const activeIncidents = incidents.filter(i => ['open', 'investigating'].includes(i.status))
  const criticalIncidents = incidents.filter(i => i.severity === 'critical' && i.status !== 'resolved')
  const healthyHosts = hosts.filter(h => h.status === 'healthy').length
  const degradedHosts = hosts.filter(h => h.status === 'degraded' || h.status === 'critical').length

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Overview</h1>
          <p>Infrastructure health snapshot</p>
        </div>
      </div>

      {/* Stat row */}
      <div className="grid-4 mb-4">
        <StatCard label="Total Hosts" value={hosts.length} sub={`${healthyHosts} healthy · ${degradedHosts} degraded`} />
        <StatCard label="Services" value={services.length} />
        <StatCard
          label="Active Incidents"
          value={activeIncidents.length}
          sub={`${criticalIncidents.length} critical`}
          accent={activeIncidents.length > 0 ? 'var(--sev-critical)' : undefined}
        />
        <StatCard
          label="Total Incidents"
          value={incidents.length}
          sub={`${incidents.filter(i => i.status === 'resolved').length} resolved`}
        />
      </div>

      <div className="grid-2" style={{ marginTop: 0 }}>
        {/* Hosts summary */}
        <div className="card">
          <div className="section-title">Hosts</div>
          {hosts.length === 0 ? (
            <div className="text-muted" style={{ fontSize: '0.85rem', padding: '16px 0' }}>No hosts registered.</div>
          ) : (
            <div className="table-wrapper" style={{ border: 'none' }}>
              <table>
                <thead>
                  <tr>
                    <th>Hostname</th>
                    <th>Status</th>
                    <th>OS</th>
                    <th>Services</th>
                  </tr>
                </thead>
                <tbody>
                  {hosts.slice(0, 8).map(h => (
                    <tr key={h.id}>
                      <td className="primary">{h.hostname}</td>
                      <td><StatusBadge status={h.status} /></td>
                      <td className="truncate" style={{ maxWidth: 140 }}>{h.os_info ?? '—'}</td>
                      <td>{h.services_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {hosts.length > 8 && (
            <div style={{ marginTop: 12 }}>
              <Link to="/hosts" className="btn btn-ghost" style={{ fontSize: '0.78rem' }}>View all {hosts.length} hosts →</Link>
            </div>
          )}
        </div>

        {/* Active incidents */}
        <div className="card">
          <div className="section-title">Active Incidents</div>
          {activeIncidents.length === 0 ? (
            <div style={{ padding: '20px 0', color: 'var(--status-healthy)', fontSize: '0.875rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>✓</span> No active incidents
            </div>
          ) : (
            <div className="table-wrapper" style={{ border: 'none' }}>
              <table>
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {activeIncidents.slice(0, 8).map(inc => (
                    <tr key={inc.id}>
                      <td className="primary">
                        <Link to={`/incidents/${inc.id}`} style={{ color: 'inherit' }}>{inc.title}</Link>
                      </td>
                      <td><SeverityBadge severity={inc.severity} /></td>
                      <td><IncidentStatusBadge status={inc.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {activeIncidents.length > 8 && (
            <div style={{ marginTop: 12 }}>
              <Link to="/incidents" className="btn btn-ghost" style={{ fontSize: '0.78rem' }}>View all incidents →</Link>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
