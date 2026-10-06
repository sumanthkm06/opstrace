import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { incidentsApi } from '../services/api'
import type { Incident } from '../types'
import { LoadingState, ErrorState, EmptyState } from '../components/States'
import { SeverityBadge, IncidentStatusBadge } from '../components/Badges'

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[] | null>(null)
  const [statusFilter, setStatusFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    incidentsApi.list()
      .then(setIncidents)
      .catch(e => setError(e.message))
  }, [])

  if (error) return <ErrorState message={`Failed to load incidents: ${error}`} />
  if (!incidents) return <LoadingState message="Loading incidents…" />

  let visible = incidents
  if (statusFilter) visible = visible.filter(i => i.status === statusFilter)
  if (severityFilter) visible = visible.filter(i => i.severity === severityFilter)

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Incidents</h1>
          <p>{incidents.length} total incident{incidents.length !== 1 ? 's' : ''}</p>
        </div>
      </div>

      <div className="filters-bar">
        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="mitigated">Mitigated</option>
          <option value="resolved">Resolved</option>
          <option value="closed">Closed</option>
        </select>
        <select className="filter-select" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <span className="text-muted" style={{ fontSize: '0.8rem' }}>{visible.length} shown</span>
      </div>

      {visible.length === 0 ? (
        <EmptyState title="No incidents found" sub="Try adjusting the filters." icon="⚡" />
      ) : (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Detected</th>
                <th>Resolved</th>
              </tr>
            </thead>
            <tbody>
              {visible.map(inc => (
                <tr key={inc.id}>
                  <td className="primary">
                    <Link to={`/incidents/${inc.id}`} style={{ color: 'var(--accent)' }}>
                      {inc.title}
                    </Link>
                  </td>
                  <td><SeverityBadge severity={inc.severity} /></td>
                  <td><IncidentStatusBadge status={inc.status} /></td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{fmtDate(inc.detected_at)}</td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{fmtDate(inc.resolved_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
