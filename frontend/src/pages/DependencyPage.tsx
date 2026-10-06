import { useEffect, useState } from 'react'
import { dependencyApi, servicesApi } from '../services/api'
import type { DependencyImpactAnalysis, Service } from '../types'
import { ErrorState, EmptyState, LoadingState } from '../components/States'

export default function DependencyPage() {
  const [services, setServices] = useState<Service[]>([])
  const [serviceId, setServiceId] = useState('')
  const [impact, setImpact] = useState<DependencyImpactAnalysis | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    servicesApi.list().then(items => {
      setServices(items)
      setServiceId(items[0]?.id ?? '')
    }).catch(e => setError(e.message)).finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (!serviceId) { setImpact(null); return }
    setLoading(true)
    setError(null)
    dependencyApi.impact(serviceId)
      .then(setImpact)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [serviceId])

  if (error) return <ErrorState message={`Dependency analysis failed: ${error}`} />
  return <div>
    <div className="page-header"><div><h1>Dependency Impact</h1><p>Bounded upstream and downstream service analysis</p></div></div>
    <div className="filters-bar">
      <label htmlFor="dependency-service">Service</label>
      <select id="dependency-service" className="filter-select" value={serviceId} onChange={e => setServiceId(e.target.value)}>
        {services.map(service => <option key={service.id} value={service.id}>{service.name} ({service.hostname ?? 'unknown host'})</option>)}
      </select>
    </div>
    {loading ? <LoadingState message="Analysing dependencies…" /> : !services.length ? <EmptyState title="No services registered" sub="Dependency analysis is available after services are ingested." /> : impact && <>
      <div className="card mb-4"><div className="section-title">{impact.service_name}</div><div className="text-muted">Impact traversal is bounded to five dependency levels and handles cycles safely.</div></div>
      <div className="grid-2">
        {[['Upstream Dependencies', impact.upstream_dependencies], ['Downstream Impacts', impact.downstream_impacts]].map(([heading, nodes]) => {
          const entries = nodes as DependencyImpactAnalysis['upstream_dependencies']
          return <section className="card" key={heading as string}>
            <div className="section-title">{heading as string} ({entries.length})</div>
            {!entries.length ? <EmptyState title="No connected services" /> : <div className="table-wrapper" style={{ border: 'none' }}><table><thead><tr><th>Service</th><th>Host</th><th>Type</th><th>Criticality</th><th>Depth</th></tr></thead><tbody>
              {entries.map(node => <tr key={node.service_id}><td className="primary">{node.service_name}</td><td>{node.host_name}</td><td>{node.dependency_type}</td><td>{node.criticality}</td><td>{node.depth}</td></tr>)}
            </tbody></table></div>}
          </section>
        })}
      </div>
    </>}
  </div>
}
