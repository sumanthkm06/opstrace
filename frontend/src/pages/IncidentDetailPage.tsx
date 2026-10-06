import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { useParams, Link } from 'react-router-dom'
import { dependencyApi, incidentsApi } from '../services/api'
import type { CorrelatedChanges, DependencyImpactAnalysis, IncidentDetail, IncidentReplay, Timeline } from '../types'
import { LoadingState, ErrorState, EmptyState } from '../components/States'
import { SeverityBadge, IncidentStatusBadge } from '../components/Badges'

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

function DetailItem({ label, value, mono = false }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="detail-item">
      <div className="detail-label">{label}</div>
      <div className={`detail-value${mono ? ' mono' : ''}`}>{value ?? '—'}</div>
    </div>
  )
}

function TimelineSection({ id }: { id: string }) {
  const [tl, setTl] = useState<Timeline | null>(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    incidentsApi.timeline(id)
      .then(t => { setTl(t); setLoading(false) })
      .catch(e => { setErr(e.message); setLoading(false) })
  }, [id])

  if (loading) return <LoadingState message="Loading timeline…" />
  if (err) return <div className="text-muted" style={{ fontSize: '0.85rem', padding: '12px 0' }}>Timeline unavailable: {err}</div>
  if (!tl || tl.events.length === 0) return <EmptyState title="No timeline events" icon="📅" />

  return (
    <div className="timeline-list">
      {tl.events.map((ev, i) => (
        <div key={i} className="timeline-item">
          <span className="timeline-ts">{fmtDate(ev.timestamp)}</span>
          <span className="timeline-label">
            <strong>{ev.event_type.replace(/_/g, ' ')}</strong>
            {ev.message ? ` — ${ev.message}` : ''}
          </span>
        </div>
      ))}
    </div>
  )
}

function IncidentContext({ incident }: { incident: IncidentDetail }) {
  const [replay, setReplay] = useState<IncidentReplay | null>(null)
  const [changes, setChanges] = useState<CorrelatedChanges | null>(null)
  const [impact, setImpact] = useState<DependencyImpactAnalysis | null>(null)
  const [messages, setMessages] = useState<string[]>([])

  useEffect(() => {
    const tasks: Promise<void>[] = [
      incidentsApi.replay(incident.id).then(setReplay).catch(e => setMessages(v => [...v, `Replay unavailable: ${e.message}`])),
      incidentsApi.correlatedChanges(incident.id).then(setChanges).catch(e => setMessages(v => [...v, `Correlated changes unavailable: ${e.message}`])),
    ]
    if (incident.service_id) tasks.push(dependencyApi.impact(incident.service_id).then(setImpact).catch(e => setMessages(v => [...v, `Dependency impact unavailable: ${e.message}`])))
    Promise.all(tasks)
  }, [incident.id, incident.service_id])

  return <>
    <section className="card mb-4">
      <div className="section-title">Replay & Candidate Changes</div>
      {messages.map(message => <div className="text-muted" key={message}>{message}</div>)}
      {changes && <>
        <div className="detail-grid">
          <DetailItem label="Candidate Deployment" value={changes.correlated_deployment ? `Version ${changes.correlated_deployment.version} · ${changes.correlated_deployment.status}` : 'None recorded'} />
          <DetailItem label="Candidate Configuration Change" value={changes.correlated_config_change?.config_file_path ?? 'None recorded'} />
        </div>
        <p className="text-muted">{changes.causation_disclaimer}</p>
      </>}
      {replay && <>
        <p className="text-muted">Read-only reconstruction · {replay.total_steps} steps · final state {replay.final_status} / {replay.final_severity}</p>
        <div className="timeline-list">{replay.snapshots.map(snapshot => <div className="timeline-item" key={snapshot.step}>
          <span className="timeline-ts">{fmtDate(snapshot.replay_timestamp)}</span>
          <span className="timeline-label"><strong>{snapshot.event_type.replace(/_/g, ' ')}</strong> — {snapshot.event_description}</span>
        </div>)}</div>
        <p className="text-muted">{replay.causation_disclaimer}</p>
      </>}
    </section>
    {incident.service_id && <section className="card mb-4">
      <div className="section-title">Service Impact</div>
      {!impact ? <div className="text-muted">Loading dependency impact…</div> : <div className="grid-2">
        <div><div className="detail-label">Upstream dependencies</div>{impact.upstream_dependencies.length ? impact.upstream_dependencies.map(n => <div key={n.service_id} className="detail-value">{n.service_name} · {n.host_name}</div>) : <div className="text-muted">None recorded</div>}</div>
        <div><div className="detail-label">Downstream impact</div>{impact.downstream_impacts.length ? impact.downstream_impacts.map(n => <div key={n.service_id} className="detail-value">{n.service_name} · {n.host_name}</div>) : <div className="text-muted">None recorded</div>}</div>
      </div>}
    </section>}
  </>
}

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [inc, setInc] = useState<IncidentDetail | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    incidentsApi.get(id)
      .then(setInc)
      .catch(e => setError(e.message))
  }, [id])

  if (error) return <ErrorState message={`Incident not found: ${error}`} />
  if (!inc) return <LoadingState message="Loading incident…" />

  return (
    <div>
      <Link to="/incidents" className="back-link">← Back to Incidents</Link>

      <div className="page-header">
        <div>
          <h1>{inc.title}</h1>
          <p style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
            {inc.id}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <SeverityBadge severity={inc.severity} />
          <IncidentStatusBadge status={inc.status} />
        </div>
      </div>

      {/* Core details */}
      <div className="card mb-4">
        <div className="section-title">Incident Details</div>
        <div className="detail-grid">
          <DetailItem label="Host" value={inc.hostname} />
          <DetailItem label="Service" value={inc.service_name} />
          <DetailItem label="Detected At" value={fmtDate(inc.detected_at)} />
          <DetailItem label="Resolved At" value={fmtDate(inc.resolved_at)} />
          <DetailItem label="Correlated Deployment" value={inc.correlated_deployment_id} mono />
          <DetailItem label="Correlated Config Change" value={inc.correlated_config_change_id} mono />
        </div>
        {inc.description && (
          <div style={{ marginTop: 16 }}>
            <div className="detail-label">Description</div>
            <div className="detail-value">{inc.description}</div>
          </div>
        )}
        {inc.root_cause_analysis && (
          <div style={{ marginTop: 12 }}>
            <div className="detail-label">Root Cause Analysis</div>
            <div className="detail-value" style={{ whiteSpace: 'pre-wrap', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
              {inc.root_cause_analysis}
            </div>
          </div>
        )}
      </div>

      {/* Timeline */}
      <div className="card mb-4">
        <div className="section-title">Incident Timeline</div>
        <TimelineSection id={inc.id} />
      </div>

      <IncidentContext incident={inc} />

      {/* Remediations */}
      <div className="card">
        <div className="section-title">Remediation Actions ({inc.remediations.length})</div>
        {inc.remediations.length === 0 ? (
          <EmptyState title="No remediations recorded" icon="🔧" />
        ) : (
          <div className="table-wrapper" style={{ border: 'none' }}>
            <table>
              <thead>
                <tr>
                  <th>Action Type</th>
                  <th>Status</th>
                  <th>Requested By</th>
                  <th>Approved By</th>
                  <th>Description</th>
                  <th>Output</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {inc.remediations.map(r => (
                  <tr key={r.id}>
                    <td className="primary">{r.action_type}</td>
                    <td><span className={`badge badge-${r.status === 'executed' ? 'healthy' : r.status === 'failed' ? 'failed' : 'degraded'}`}>{r.status}</span></td>
                    <td>{r.requested_by}</td>
                    <td>{r.approved_by ?? '—'}</td>
                    <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.description}</td>
                    <td className="mono" style={{ fontSize: '0.75rem', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {r.execution_output ?? '—'}
                    </td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{fmtDate(r.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
