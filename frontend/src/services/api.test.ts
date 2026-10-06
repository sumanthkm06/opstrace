import { afterEach, describe, expect, it, vi } from 'vitest'
import { dependencyApi, incidentsApi, logsApi, servicesApi } from './api'

const fetchMock = vi.fn()

afterEach(() => {
  fetchMock.mockReset()
  vi.unstubAllGlobals()
})

describe('OpsTrace API client', () => {
  it('uses the existing services resource endpoint', async () => {
    vi.stubGlobal('fetch', fetchMock.mockImplementation(() => Promise.resolve(new Response('[]', { status: 200 }))))
    await servicesApi.list('host-1')
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/services?host_id=host-1', expect.any(Object))
  })

  it('loads the existing incident timeline, replay, and correlation endpoints', async () => {
    vi.stubGlobal('fetch', fetchMock.mockImplementation(() => Promise.resolve(new Response('{}', { status: 200 }))))
    await incidentsApi.timeline('incident-1')
    await incidentsApi.replay('incident-1')
    await incidentsApi.correlatedChanges('incident-1')
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      '/api/v1/incidents/incident-1/timeline',
      '/api/v1/incidents/incident-1/replay',
      '/api/v1/incidents/incident-1/correlated-changes',
    ])
  })

  it('uses existing log analysis and dependency impact endpoints', async () => {
    vi.stubGlobal('fetch', fetchMock.mockImplementation(() => Promise.resolve(new Response('{}', { status: 200 }))))
    await logsApi.analyze(500, 'ERROR')
    await dependencyApi.impact('service-1', 3)
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      '/api/v1/logs/analyze?limit=500&level=ERROR',
      '/api/v1/dependencies/service/service-1/impact?max_depth=3',
    ])
  })

  it('surfaces API error details to the dashboard', async () => {
    vi.stubGlobal('fetch', fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: 'Service unavailable' }), { status: 503 })))
    await expect(servicesApi.list()).rejects.toThrow('Service unavailable')
  })
})
