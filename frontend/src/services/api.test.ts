import { afterEach, describe, expect, it, vi } from 'vitest'
import { dependencyApi, incidentsApi, logsApi, servicesApi } from './api'
import type { AnalysisResult } from '../types'

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

  it('preserves the backend log analysis response contract', async () => {
    const analysis = {
      analyzed_at: '2026-10-08T10:00:00Z',
      total_logs_analyzed: 2,
      total_info: 1,
      total_warnings: 0,
      total_errors: 1,
      total_critical: 0,
      total_unknown: 0,
      error_groups: [{
        fingerprint: 'abc123',
        count: 1,
        first_seen: '2026-10-08T09:59:00Z',
        last_seen: '2026-10-08T09:59:00Z',
        sample_message: 'database connection failed',
        level: 'ERROR',
        source: 'app.log',
      }],
      unique_error_fingerprints: 1,
      error_rate_per_minute: 1,
      error_rate_per_hour: 60,
      analysis_window_seconds: 60,
      window_start: '2026-10-08T09:59:00Z',
      window_end: '2026-10-08T10:00:00Z',
      analysis_warnings: [],
      analysis_errors: [],
    } satisfies AnalysisResult
    vi.stubGlobal('fetch', fetchMock.mockResolvedValue(
      new Response(JSON.stringify(analysis), { status: 200 }),
    ))

    const result = await logsApi.analyze()

    expect(result.total_logs_analyzed.toLocaleString()).toBe('2')
    expect(result.total_errors).toBe(1)
    expect(result.error_rate_per_minute).toBe(1)
    expect(result.error_groups[0].sample_message).toBe('database connection failed')
  })

  it('surfaces API error details to the dashboard', async () => {
    vi.stubGlobal('fetch', fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: 'Service unavailable' }), { status: 503 })))
    await expect(servicesApi.list()).rejects.toThrow('Service unavailable')
  })
})
