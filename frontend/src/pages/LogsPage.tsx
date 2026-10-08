import { useEffect, useState } from 'react'
import { logsApi } from '../services/api'
import type { AnalysisResult } from '../types'
import { LoadingState, ErrorState, EmptyState } from '../components/States'

function fmtDate(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : '—'
}

export default function LogsPage() {
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [limit, setLimit] = useState(1000)
  const [level, setLevel] = useState('')

  useEffect(() => {
    setResult(null)
    setError(null)
    logsApi.analyze(limit, level || undefined)
      .then(setResult)
      .catch(e => setError(e.message))
  }, [limit, level])

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Logs & Analysis</h1>
          <p>Error classification and fingerprint groups</p>
        </div>
      </div>

      <div className="filters-bar">
        <select className="filter-select" value={level} onChange={e => setLevel(e.target.value)}>
          <option value="">All levels</option>
          <option value="ERROR">ERROR</option>
          <option value="WARNING">WARNING</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="INFO">INFO</option>
        </select>
        <select className="filter-select" value={limit} onChange={e => setLimit(Number(e.target.value))}>
          <option value={100}>Last 100</option>
          <option value={500}>Last 500</option>
          <option value={1000}>Last 1 000</option>
          <option value={5000}>Last 5 000</option>
          <option value={10000}>Last 10 000</option>
        </select>
      </div>

      {error ? (
        <ErrorState message={`Analysis failed: ${error}`} />
      ) : !result ? (
        <LoadingState message="Analysing logs…" />
      ) : (
        <>
          {/* Stats */}
          <div className="grid-4 mb-4">
            <div className="card">
              <div className="card-title">Total Logs</div>
              <div className="stat-value">{result.total_logs_analyzed.toLocaleString()}</div>
            </div>
            <div className="card">
              <div className="card-title">Errors</div>
              <div className="stat-value" style={{ color: 'var(--sev-critical)' }}>
                {result.total_errors.toLocaleString()}
              </div>
              <div className="stat-sub">
                {result.error_rate_per_minute.toLocaleString(undefined, { maximumFractionDigits: 1 })} errors/min
              </div>
            </div>
            <div className="card">
              <div className="card-title">Warnings</div>
              <div className="stat-value" style={{ color: 'var(--sev-medium)' }}>
                {result.total_warnings.toLocaleString()}
              </div>
            </div>
            <div className="card">
              <div className="card-title">Info</div>
              <div className="stat-value" style={{ color: 'var(--text-secondary)' }}>
                {result.total_info.toLocaleString()}
              </div>
            </div>
          </div>

          {/* Warnings */}
          {result.analysis_warnings.length > 0 && (
            <div className="card mb-4" style={{ borderColor: 'var(--sev-medium)', background: 'rgba(251,191,36,.05)' }}>
              <div className="section-title" style={{ color: 'var(--sev-medium)' }}>Analysis Warnings</div>
              {result.analysis_warnings.map((w, i) => (
                <div key={i} style={{ fontSize: '0.85rem', color: 'var(--sev-medium)', padding: '3px 0' }}>⚠ {w}</div>
              ))}
            </div>
          )}

          {/* Error groups */}
          <div className="card">
            <div className="section-title">Error Groups ({result.error_groups.length} fingerprints)</div>
            {result.error_groups.length === 0 ? (
              <EmptyState title="No error groups" sub="No errors detected in the selected window." icon="✓" />
            ) : (
              <div className="table-wrapper" style={{ border: 'none' }}>
                <table>
                  <thead>
                    <tr>
                      <th>Fingerprint</th>
                      <th>Level</th>
                      <th>Count</th>
                      <th>First Seen</th>
                      <th>Last Seen</th>
                      <th>Sample Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.error_groups.map(g => (
                      <tr key={g.fingerprint}>
                        <td className="mono" style={{ maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {g.fingerprint}
                        </td>
                        <td>
                          <span className={`badge badge-${g.level === 'ERROR' || g.level === 'CRITICAL' ? 'critical' : g.level === 'WARNING' ? 'degraded' : 'healthy'}`}>
                            {g.level}
                          </span>
                        </td>
                        <td className="primary">{g.count.toLocaleString()}</td>
                        <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{fmtDate(g.first_seen)}</td>
                        <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{fmtDate(g.last_seen)}</td>
                        <td style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', fontSize: '0.8rem' }}>
                          {g.sample_message}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
