/**
 * OpsTrace centralised API client.
 *
 * All fetch calls go through here so:
 *  - The base URL is a single config point
 *  - Error handling is uniform
 *  - TypeScript return types are guaranteed
 *
 * During local development Vite proxies /api → http://localhost:8000
 * so no CORS issues arise.
 */

import type {
  APIHealthResponse,
  AnalysisResult,
  DependencyImpactAnalysis,
  Host,
  Incident,
  IncidentDetail,
  IncidentReplay,
  CorrelatedChanges,
  RemediationDetail,
  Service,
  Timeline,
} from '../types';

const BASE = '/api/v1';

// ─── Primitives ───────────────────────────────────────────────────────────────

async function get<T>(path: string, params?: Record<string, string>): Promise<T> {
  let url = `${BASE}${path}`;
  if (params && Object.keys(params).length > 0) {
    url += '?' + new URLSearchParams(params).toString();
  }
  const res = await fetch(url, {
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      detail = body?.detail ?? detail;
    } catch {
      // ignore parse error
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

// ─── Health ───────────────────────────────────────────────────────────────────

export const healthApi = {
  get: () => get<APIHealthResponse>('/health'),
};

// ─── Hosts ───────────────────────────────────────────────────────────────────

export const hostsApi = {
  list: (statusFilter?: string) =>
    get<Host[]>('/hosts', statusFilter ? { status: statusFilter } : undefined),
};

// ─── Services ────────────────────────────────────────────────────────────────

export const servicesApi = {
  list: (hostId?: string) =>
    get<Service[]>('/services', hostId ? { host_id: hostId } : undefined),
};

// ─── Incidents ───────────────────────────────────────────────────────────────

export const incidentsApi = {
  list: (filters?: { status?: string; severity?: string }) =>
    get<Incident[]>('/incidents', filters as Record<string, string> | undefined),
  get: (id: string) => get<IncidentDetail>(`/incidents/${id}`),
  timeline: (id: string) => get<Timeline>(`/incidents/${id}/timeline`),
  replay: (id: string) => get<IncidentReplay>(`/incidents/${id}/replay`),
  correlatedChanges: (id: string) => get<CorrelatedChanges>(`/incidents/${id}/correlated-changes`),
};

// ─── Remediations ────────────────────────────────────────────────────────────

export const remediationsApi = {
  list: (incidentId?: string) =>
    get<RemediationDetail[]>('/remediations', incidentId ? { incident_id: incidentId } : undefined),
};

// ─── Logs / Analysis ─────────────────────────────────────────────────────────

export const logsApi = {
  analyze: (limit = 1000, level?: string) =>
    get<AnalysisResult>('/logs/analyze', level ? { limit: String(limit), level } : { limit: String(limit) }),
};

// ─── Dependencies ────────────────────────────────────────────────────────────

export const dependencyApi = {
  impact: (serviceId: string, maxDepth = 5) =>
    get<DependencyImpactAnalysis>(`/dependencies/service/${serviceId}/impact`, {
      max_depth: String(maxDepth),
    }),
};
