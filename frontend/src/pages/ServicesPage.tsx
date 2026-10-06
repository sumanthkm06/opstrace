import { useEffect, useState } from 'react'
import { servicesApi } from '../services/api'
import type { Service } from '../types'
import { LoadingState, ErrorState, EmptyState } from '../components/States'
import { StatusBadge } from '../components/Badges'

export default function ServicesPage() {
  const [services, setServices] = useState<Service[] | null>(null)
  const [filter, setFilter] = useState('')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    servicesApi.list()
      .then(setServices)
      .catch(e => setError(e.message))
  }, [])

  if (error) return <ErrorState message={`Failed to load services: ${error}`} />
  if (!services) return <LoadingState message="Loading services…" />

  const visible = filter ? services.filter(s => s.status === filter) : services

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Services</h1>
          <p>{services.length} monitored service{services.length !== 1 ? 's' : ''}</p>
        </div>
      </div>

      <div className="filters-bar">
        <select className="filter-select" value={filter} onChange={e => setFilter(e.target.value)}>
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="degraded">Degraded</option>
          <option value="inactive">Inactive</option>
          <option value="failed">Failed</option>
        </select>
        <span className="text-muted" style={{ fontSize: '0.8rem' }}>{visible.length} shown</span>
      </div>

      {visible.length === 0 ? (
        <EmptyState
          title="No services found"
          sub={filter ? `No services with status "${filter}"` : 'No services are registered yet.'}
          icon="⚙"
        />
      ) : (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Status</th>
                <th>Type</th>
                <th>Host</th>
                <th>Port</th>
                <th>Systemd Unit</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {visible.map(s => (
                <tr key={s.id}>
                  <td className="primary">{s.name}</td>
                  <td><StatusBadge status={s.status} /></td>
                  <td style={{ color: 'var(--text-secondary)' }}>{s.service_type}</td>
                  <td style={{ color: 'var(--accent)' }}>{s.hostname ?? '—'}</td>
                  <td className="mono">{s.port ?? '—'}</td>
                  <td className="mono" style={{ fontSize: '0.78rem' }}>{s.systemd_unit ?? '—'}</td>
                  <td className="truncate" style={{ maxWidth: 200, color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                    {s.description ?? '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
