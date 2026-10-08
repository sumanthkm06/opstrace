// OpsTrace TypeScript type definitions
// Mirrors the FastAPI backend response schemas exactly.

// ─── Health ──────────────────────────────────────────────────────────────────

export interface DatabaseHealthStatus {
  connected: boolean;
  message: string;
}

export interface HealthResponse {
  status: 'ok' | 'degraded' | 'error';
  service: string;
  version: string;
  environment: string;
  timestamp: string;
}

export interface APIHealthResponse extends HealthResponse {
  api_version: string;
  database: DatabaseHealthStatus;
}

// ─── Hosts ───────────────────────────────────────────────────────────────────

export interface Host {
  id: string;
  hostname: string;
  ip_address: string | null;
  status: 'healthy' | 'degraded' | 'critical' | 'offline';
  os_info: string | null;
  kernel_version: string | null;
  cpu_count: number | null;
  total_memory_bytes: number | null;
  total_disk_bytes: number | null;
  agent_version: string | null;
  last_heartbeat_at: string | null;
  created_at: string | null;
  updated_at: string | null;
  services_count: number;
}

// ─── Services ────────────────────────────────────────────────────────────────

export interface Service {
  id: string;
  name: string;
  host_id: string | null;
  hostname: string | null;
  service_type: string;
  port: number | null;
  status: 'active' | 'inactive' | 'failed' | 'degraded';
  description: string | null;
  systemd_unit: string | null;
  created_at: string | null;
  updated_at: string | null;
}

// ─── Incidents ───────────────────────────────────────────────────────────────

export interface Remediation {
  id: string;
  action_type: string;
  description: string;
  status: string;
  requested_by: string;
  approved_by: string | null;
  execution_output: string | null;
  created_at: string | null;
}

export interface RemediationDetail extends Remediation {
  incident_id: string;
  rationale: string | null;
  approved_at: string | null;
  executed_at: string | null;
}

export interface Incident {
  id: string;
  title: string;
  description: string | null;
  status: 'open' | 'investigating' | 'mitigated' | 'resolved' | 'closed';
  severity: 'critical' | 'high' | 'medium' | 'low';
  host_id: string | null;
  service_id: string | null;
  detected_at: string | null;
  created_at: string | null;
  updated_at: string | null;
  resolved_at: string | null;
}

export interface IncidentDetail extends Incident {
  hostname: string | null;
  service_name: string | null;
  root_cause_analysis: string | null;
  correlated_deployment_id: string | null;
  correlated_config_change_id: string | null;
  remediations: Remediation[];
}

// ─── Timeline ────────────────────────────────────────────────────────────────

export interface TimelineEvent {
  event_id: string | null;
  incident_id: string;
  sequence: number;
  event_type: string;
  timestamp: string;
  message: string;
  source: string;
  severity: string | null;
  metadata: Record<string, unknown>;
}

export interface Timeline {
  incident_id: string;
  incident_title: string;
  status: string;
  severity: string;
  started_at: string;
  resolved_at: string | null;
  duration_seconds: number | null;
  total_events: number;
  events: TimelineEvent[];
  summary: string;
  causation_disclaimer: string;
}

export interface ReplaySnapshot {
  step: number;
  incident_id: string;
  replay_timestamp: string;
  event_type: string;
  event_description: string;
  observed_severity: string;
  observed_status: string;
  correlated_changes_known: Array<Record<string, unknown>>;
  remediations_known: Array<Record<string, unknown>>;
  state_summary: string;
  is_reconstructed_state: boolean;
}

export interface IncidentReplay {
  incident_id: string;
  total_steps: number;
  snapshots: ReplaySnapshot[];
  final_status: string;
  final_severity: string;
  reconstructed_at: string;
  causation_disclaimer: string;
}

export interface CorrelatedChanges {
  incident_id: string;
  incident_title: string;
  detected_at: string | null;
  correlated_deployment: { id: string; version: string; status: string; deployed_by: string; deployed_at: string | null } | null;
  correlated_config_change: { id: string; config_file_path: string; change_type: string; changed_by: string; diff: string | null; changed_at: string | null } | null;
  correlation_details: Record<string, unknown> | null;
  causation_disclaimer: string;
  correlation_does_not_prove_causation: boolean;
}

// ─── Logs / Analysis ─────────────────────────────────────────────────────────

export interface ErrorGroup {
  fingerprint: string;
  count: number;
  first_seen: string | null;
  last_seen: string | null;
  sample_message: string;
  level: string;
  source: string;
}

export interface AnalysisResult {
  analyzed_at: string;
  total_logs_analyzed: number;
  total_info: number;
  total_warnings: number;
  total_errors: number;
  total_critical: number;
  total_unknown: number;
  error_groups: ErrorGroup[];
  unique_error_fingerprints: number;
  error_rate_per_minute: number;
  error_rate_per_hour: number;
  analysis_window_seconds: number;
  window_start: string | null;
  window_end: string | null;
  analysis_warnings: string[];
  analysis_errors: string[];
}

// ─── Dependency / Impact ─────────────────────────────────────────────────────

export interface DependencyNode {
  service_id: string;
  service_name: string;
  host_id: string;
  host_name: string;
  criticality: string;
  dependency_type: string;
  depth: number;
}

export interface DependencyImpactAnalysis {
  service_id: string;
  service_name: string;
  upstream_dependencies: DependencyNode[];
  downstream_impacts: DependencyNode[];
}

// ─── API State ────────────────────────────────────────────────────────────────

export type LoadState = 'idle' | 'loading' | 'success' | 'error';

export interface AsyncState<T> {
  data: T | null;
  state: LoadState;
  error: string | null;
}
