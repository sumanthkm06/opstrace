import { useEffect, useState } from 'react'
import { hostsApi } from '../services/api'
import type { Host } from '../types'
import { LoadingState, ErrorState, EmptyState } from '../components/States'
import { StatusBadge } from '../components/Badges'

function fmt(bytes: number | null): string {
  if (!bytes) return '—'
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`
  return `${(bytes / 1e6).toFixed(0)} MB`
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

export default function HostsPage() {
  const [hosts, setHosts] = useState<Host[] | null>(null)
  const [filter, setFilter] = useState('')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    hostsApi.list()
      .then(setHosts)
      .catch(e => setError(e.message))
  }, [])

  if (error) return <ErrorState message={`Failed to load hosts: ${error}`} />
  if (!hosts) return <LoadingState message="Loading hosts…" />

  const visible = filter ? hosts.filter(h => h.status === filter) : hosts

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Hosts</h1>
          <p>{hosts.length} monitored host{hosts.length !== 1 ? 's' : ''}</p>
        </div>
      </div>

      <div className="filters-bar">
        <select className="filter-select" value={filter} onChange={e => setFilter(e.target.value)}>
          <option value="">All statuses</option>
          <option value="healthy">Healthy</option>
          <option value="degraded">Degraded</option>
          <option value="critical">Critical</option>
          <option value="offline">Offline</option>
        </select>
        <span className="text-muted" style={{ fontSize: '0.8rem' }}>{visible.length} shown</span>
      </div>

      {visible.length === 0 ? (
        <EmptyState
          title="No hosts found"
          sub={filter ? `No hosts with status "${filter}"` : 'No hosts are registered yet.'}
          icon="⬡"
        />
      ) : (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>Status</th>
                <th>OS</th>
                <th>CPU</th>
                <th>Memory</th>
                <th>Disk</th>
                <th>Agent</th>
                <th>Services</th>
                <th>Last Heartbeat</th>
              </tr>
            </thead>
            <tbody>
              {visible.map(h => (
                <tr key={h.id}>
                  <td className="primary">{h.hostname}</td>
                  <td className="mono">{h.ip_address ?? '—'}</td>
                  <td><StatusBadge status={h.status} /></td>
                  <td>{h.os_info ?? '—'}</td>
                  <td>{h.cpu_count ?? '—'}</td>
                  <td>{fmt(h.total_memory_bytes)}</td>
                  <td>{fmt(h.total_disk_bytes)}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{h.agent_version ?? '—'}</td>
                  <td>{h.services_count}</td>
                  <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{fmtDate(h.last_heartbeat_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
