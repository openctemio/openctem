/**
 * Sensor API Types
 *
 * TypeScript types for Sensor Management
 * API endpoint: /api/v1/sensors
 */

// Sensor types - maps to backend SensorType
// worker = daemon, collector = asset discovery, sensor = EASM
export type SensorType = 'worker' | 'collector' | 'sensor'

/**
 * Sensor role (RFC-023 §9.1, decision D18): what a sensor does, as opposed to
 * its legacy `type`, which mixes what it does with how it runs. The API does
 * not send a role yet (it arrives with RFC-023 Phase 2, together with the
 * endpoint-agent and monitor roles); until then the role is derived from the
 * legacy type exactly as the RFC maps it: worker and the old EASM
 * 'sensor' type scan, a collector collects.
 */
export type SensorRole = 'scanner' | 'collector'

export const SENSOR_ROLES: readonly SensorRole[] = ['scanner', 'collector']

export function sensorRoleOf(type: SensorType): SensorRole {
  return type === 'collector' ? 'collector' : 'scanner'
}

// Admin-controlled status
export type SensorStatus = 'active' | 'disabled' | 'revoked'

// Heartbeat-based health (automatic). late and stale are the heartbeat
// ladder's steps between online and offline (api RFC-035 §5.6).
export type SensorHealth = 'unknown' | 'online' | 'late' | 'stale' | 'offline' | 'error'

/** Where a sensor stands on the heartbeat ladder (api RFC-035 §5.6). */
export type SensorHeartbeatState = 'online' | 'late' | 'stale' | 'offline'

export type ExecutionMode = 'standalone' | 'daemon'

/**
 * Operational state computed by the API (GET /sensors): the admin status, the
 * heartbeat age and the problems a heartbeating sensor reports, as one value.
 * Older APIs do not send it; `sensorState()` computes the same ladder then.
 */
export type SensorState =
  | 'online'
  | 'degraded'
  | 'late'
  | 'stale'
  | 'offline'
  | 'idle'
  | 'never_connected'
  | 'disabled'
  | 'revoked'

/** How a sensor's version compares with the platform's release channel. */
export type SensorVersionStatus = 'latest' | 'update_available' | 'unsupported' | 'unknown'

/**
 * How the SDK a sensor is built with compares with the platform's supported
 * SDK range (GET /sensors/stats sdk_min_version / sdk_latest_version).
 */
export type SensorSdkStatus = 'current' | 'outdated' | 'unsupported' | 'unknown'

/** One problem found on a sensor (stable `code`; `message` is a fallback). */
export interface SensorHealthReason {
  code:
    | 'outbox_backlog'
    | 'outbox_dead_letters'
    | 'outbox_evicted'
    | 'key_expired'
    | 'key_expiring'
    | 'identity_cloned'
    | 'version_unsupported'
    | 'no_tools'
    | 'error_reported'
    | 'content_stale'
    | 'content_refresh_failed'
    | 'sdk_unsupported'
    | 'heartbeat_late'
    | 'control_slow'
    | 'config_check_failed'
    | 'config_check_warning'
    | 'config_report_stale'
    | (string & {})
  severity: 'warning' | 'critical'
  message: string
}

/** The sensor's last reported outbox (results waiting to be delivered). */
export interface SensorOutbox {
  pending_count: number
  pending_bytes: number
  oldest_age_seconds: number
  dead_letter_count: number
  evicted_count: number
  /** Server time the snapshot was stored. */
  reported_at: string
}

/**
 * How well the sensor's heartbeat loop keeps time, as it last reported it
 * (sdk-go, api RFC-035 §5.5). Values are reported by the sensor (clamped).
 */
export interface SensorControl {
  /** The heartbeat interval the sensor follows, in seconds. */
  interval_s: number
  /** Seconds between its last two delivered heartbeats. */
  gap_s: number
  /** How late its heartbeat timer fired (CPU starvation), in ms. */
  lag_ms: number
  /** How long building the heartbeat report took, in ms. */
  build_ms: number
  /** Round trip of its previous heartbeat, in ms. */
  rtt_ms: number
  /** Heartbeats lost before the last one. */
  failures: number
  /** Server time the report was stored. */
  reported_at: string | null
}

/**
 * What the platform last saw of the sensor's protocol (RFC-029): null before
 * the first heartbeat that recorded it; `deprecated` for protocol v1.
 */
export interface SensorProtocol {
  version: number
  user_agent: string
  seen_at: string
  deprecated: boolean
}

/**
 * Scanner content (api RFC-031): the data a tool scans with (trivy's
 * vulnerability DB, the nuclei templates, the semgrep rules), as the sensor
 * last reported it, with the staleness the API computed from the tenant's
 * content policy.
 */
export type SensorContentName =
  'trivy-db' | 'trivy-java-db' | 'nuclei-templates' | 'semgrep-rules' | (string & {})

export interface SensorContent {
  /** The tool the content belongs to ("trivy"). */
  tool: string
  name: SensorContentName
  /** Release tag, DB build time or bundle digest prefix; "" when none. */
  version: string
  /** When the content was published (staleness is measured from it). */
  updated_at?: string | null
  /** When this sensor installed it. */
  fetched_at?: string | null
  /** When the sensor last confirmed this is the newest (or pinned) version. */
  checked_at?: string | null
  source?: string
  /** "sha256:..." */
  digest?: string
  /** false: the tool fetches it by itself on each scan (not controlled). */
  managed: boolean
  /** The last refresh failure; the sensor keeps the version above. */
  error?: string
  age_seconds?: number | null
  /** The policy's limit; 0 or absent = no limit. */
  max_age_hours?: number | null
  stale: boolean
  /** The version the policy pins ("" = newest). */
  pinned_version?: string
  /** The sensor runs another version than the pinned one. */
  pin_mismatch?: boolean
}

/** One content kind's policy. */
export interface ContentPin {
  max_age_hours?: number
  /** A DB digest ("sha256:...") or a template tag ("v10.4.9"); "" = newest. */
  version?: string
  /** semgrep-rules only: registry rulesets; empty = semgrep's own per-scan fetch. */
  rulesets?: string[]
}

export interface ContentPolicy {
  refresh_interval_hours?: number
  content: Partial<Record<SensorContentName, ContentPin>>
}

/** GET /api/v1/sensors/content-policy */
export interface ContentPolicyResponse {
  policy: ContentPolicy
  defaults: ContentPolicy
  updated_at: string | null
  updated_by: string | null
}

/** PUT /api/v1/sensors/content-policy */
export interface UpdateContentPolicyRequest {
  policy: ContentPolicy
  apply_now: boolean
}

export interface UpdateContentPolicyResponse {
  policy: ContentPolicy
  commands_created: number
  skipped: number
}

/** POST /api/v1/sensors/{id}/content/refresh and /sensors/content/refresh */
export interface RefreshContentRequest {
  /** Empty = all managed content. */
  content: SensorContentName[]
  force: boolean
}

export interface RefreshSensorContentResponse {
  command_id: string
  already_pending: boolean
}

export interface RefreshFleetContentResponse {
  commands_created: number
  skipped: number
}

// Sensor capabilities
export const SENSOR_CAPABILITIES = [
  'sast',
  'sca',
  'dast',
  'secrets',
  'iac',
  'infra',
  'collector',
  'container',
  'cloud',
] as const

export type SensorCapability = (typeof SENSOR_CAPABILITIES)[number]

// Sensor tools
export const SENSOR_TOOLS = [
  'semgrep',
  'trivy',
  'nuclei',
  'betterleaks',
  'checkov',
  'tfsec',
  'grype',
  'syft',
  'custom',
] as const

export type SensorTool = (typeof SENSOR_TOOLS)[number]

/**
 * Sensor entity (maps to Sensor in backend)
 */
export interface Sensor {
  id: string
  tenant_id: string
  name: string
  type: SensorType
  description?: string
  capabilities: SensorCapability[]
  execution_mode: ExecutionMode
  status: SensorStatus // Admin-controlled: active, disabled, revoked
  health: SensorHealth // Automatic heartbeat: unknown, online, late, stale, offline, error
  status_message?: string
  api_key_prefix: string
  version?: string
  hostname?: string
  ip_address?: string
  // System metrics (0 when the sensor does not report them)
  cpu_percent: number
  memory_percent: number
  region?: string
  // Load balancing: current_jobs is what the sensor is running now
  max_concurrent_jobs: number
  current_jobs: number
  available_slots?: number
  load_factor?: number
  // Other fields
  labels: Record<string, string>
  config: Record<string, unknown>
  metadata: Record<string, unknown>
  last_seen_at?: string
  last_error_at?: string | null
  last_offline_at?: string | null
  /** When the current API key stops working; null = never. */
  key_expires_at?: string | null
  /**
   * The current key is a legacy `rda_` key. It renews automatically to the
   * `octs_` format; `rda_` keys are retired after enrollment ships.
   */
  legacy_key?: boolean
  /** Process start, from the uptime the heartbeat reports. */
  started_at?: string | null
  uptime_seconds?: number | null
  total_findings: number
  total_scans: number
  error_count: number
  created_at: string
  updated_at: string
  /** Last reported outbox; null when the sensor never reported one. */
  outbox?: SensorOutbox | null
  /** Lost or stuck results in the last outbox snapshot. */
  outbox_warning?: boolean
  // Computed fleet health (newer APIs; see sensorState()).
  state?: SensorState
  health_reasons?: SensorHealthReason[]
  version_status?: SensorVersionStatus
  is_platform_sensor?: boolean
  /** Protocol telemetry (RFC-029); absent on APIs without it. */
  protocol?: SensorProtocol | null
  /** Scanner content (RFC-031); absent on APIs without it. */
  content?: SensorContent[]
  /** The sensor accepts refresh_content commands (it manages content). */
  content_refresh_supported?: boolean
  /**
   * What the sensor last reported it has (api RFC-029 §4.3.1); null before
   * its first report, absent on APIs without it. `capabilities` and
   * `max_concurrent_jobs` above are the administrator's limits.
   */
  reported?: SensorReported | null
  /**
   * What dispatch uses: the reported installed tools (none before a
   * report; the sensor grant narrows them), and the reported capabilities
   * and capacity narrowed by the limits.
   */
  effective?: SensorEffective
  /** The current manifest's digest (RFC-033); "" before the first one. */
  manifest_digest?: string
  /** When it became current. */
  manifest_at?: string | null
  /** sensor: registered by the sensor; heartbeat: derived by the platform. */
  manifest_source?: 'sensor' | 'heartbeat' | '' | (string & {})
  /**
   * The sensor-local policy the sensor reports (api RFC-040 §5.7): enforced
   * on the sensor, shown here. Absent on APIs without it.
   */
  local_policy?: SensorLocalPolicy
  /**
   * The load the sensor last reported on its heartbeat (api RFC-030 §5.8);
   * null when it never reported one, absent on APIs without it.
   */
  load?: SensorLoad | null
  /** Last control-channel report (api RFC-035); null when never reported. */
  control?: SensorControl | null
  /** The interval the sensor follows, stored at its last heartbeat; null before the first. */
  heartbeat_interval_seconds?: number | null
  /** When its next heartbeat is due. */
  heartbeat_due_at?: string | null
  /** Where it stands on the heartbeat ladder now; "" when it never connected. */
  heartbeat_state?: SensorHeartbeatState | ''
  /** Limits the report contradicts (a tool set here that is not installed). */
  capability_mismatch?: SensorCapabilityMismatch | null
  /** The SDK the sensor binary is built with ("openctem-sdk-go"); "" when unknown. */
  sdk_name?: string
  /** Its version ("v0.9.0"); "" when unknown. */
  sdk_version?: string
  sdk_status?: SensorSdkStatus
  /** The sensor binary's product name ("openctemio-sensor"); "" when unknown. */
  sensor_product?: string
  /** The commit the sensor binary was built from; "" when unknown. */
  sensor_commit?: string
  /** When the sensor binary was built. */
  sensor_build_time?: string | null
  /**
   * The setup report's health (research/26 §4.6): null before the first
   * report, absent on APIs without config reports.
   */
  config_health?: SensorConfigHealth | null
}

/** One tool of a sensor's reported inventory. */
export interface SensorReportedTool {
  name: string
  /** "scanner" or "collector"; absent when the sensor did not say. */
  kind?: 'scanner' | 'collector' | ''
  version?: string
  installed: boolean
  /**
   * What this tool serves besides its own name ("dast", "validate:nuclei");
   * absent from sensors on sdk-go before v0.13 (only the flat list).
   */
  capabilities?: string[] | null
}

/** A sensor's last capability report; a null list was never reported. */
export interface SensorReported {
  tools: SensorReportedTool[] | null
  capabilities: string[] | null
  /**
   * The sensor operator's ceiling on concurrent jobs (SENSOR_MAX_JOBS); null
   * when none. What it can run now is `load.capacity.slots_total`.
   */
  max_concurrent_jobs: number | null
  os?: string
  arch?: string
  reported_at: string | null
}

/** A sensor's job slots as it last reported them. */
export interface SensorLoadCapacity {
  /** How many jobs it can run at once now, sized from its CPU and memory. */
  slots_total: number
  slots_free: number
  active_jobs: number
}

/** A sensor's last load report; a part is null when never reported. */
export interface SensorLoad {
  capacity: SensorLoadCapacity | null
  reported_at: string | null
  /** False once the report is older than 3 minutes. */
  fresh: boolean
}

/** The tools, capabilities and capacity dispatch uses for a sensor. */
export interface SensorEffective {
  tools: string[]
  capabilities: string[]
  max_concurrent_jobs: number
}

export interface SensorCapabilityMismatch {
  capabilities_not_reported?: string[]
}

/** A job dispatched to a sensor (GET /api/v1/commands). */
export interface SensorCommand {
  id: string
  sensor_id?: string
  type: 'scan' | 'collect' | 'health_check' | 'config_update' | 'cancel' | (string & {})
  priority: string
  status:
    | 'pending'
    | 'acknowledged'
    | 'running'
    | 'completed'
    | 'failed'
    | 'canceled'
    | 'expired'
    | (string & {})
  payload?: Record<string, unknown> | null
  error_message?: string
  created_at: string
  acknowledged_at?: string | null
  started_at?: string | null
  completed_at?: string | null
}

export interface SensorCommandListResponse {
  data: SensorCommand[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

/**
 * Create sensor request
 */
export interface CreateSensorRequest {
  name: string
  type: SensorType
  description?: string
  capabilities?: SensorCapability[]
  execution_mode?: ExecutionMode
  max_concurrent_jobs?: number
  labels?: Record<string, string>
  config?: Record<string, unknown>
}

/**
 * Create sensor response (includes API key)
 */
export interface CreateSensorResponse {
  sensor: Sensor // Backend returns "sensor" field
  api_key: string // Only returned on create
}

/**
 * Update sensor request
 */
export interface UpdateSensorRequest {
  name?: string
  description?: string
  capabilities?: SensorCapability[]
  execution_mode?: ExecutionMode
  status?: SensorStatus
  max_concurrent_jobs?: number
  labels?: Record<string, string>
  config?: Record<string, unknown>
}

/**
 * Regenerate API key response
 */
export interface RegenerateAPIKeyResponse {
  api_key: string
  api_key_prefix: string
}

/**
 * Sensor list response
 */
export interface SensorListResponse {
  items: Sensor[]
  total: number
  page: number
  per_page: number
}

/**
 * Sensor list filters
 */
export interface SensorListFilters {
  type?: SensorType
  status?: SensorStatus
  search?: string
  page?: number
  /** The API reads per_page (max 100); page_size is ignored by it. */
  per_page?: number
  /** An exact normalized SDK version ("v0.9.0") or "unknown". */
  sdk_version?: string
}

/**
 * Available capabilities response
 * Returns all unique capability names from all sensors accessible to the tenant
 */
export interface AvailableCapabilitiesResponse {
  capabilities: string[]
}

// ============================================
// SENSOR MANIFEST (api RFC-033: GET /api/v1/sensors/{id}/manifest[s])
// ============================================

/**
 * A tool's tool-contract manifest (sdk-go docs/rfcs/sensor-sdk-v2.md), as the
 * sensor declared it: by digest, with what the tool is and what it may
 * produce. Ingest keeps only the declared output types of a ported tool.
 */
export interface SensorToolContract {
  api_version: string
  digest: string
  version: string
  class: 'target-scan' | 'connector' | 'parser' | 'enricher' | (string & {})
  tier: 'T0' | 'T1' | 'T2' | (string & {})
  network?: 'none' | 'targets' | 'egress-proxy' | 'vendor' | (string & {})
  consumes?: string[] | null
  produces: string[]
}

/** One tool of a sensor manifest. */
export interface SensorManifestTool {
  name: string
  kind?: 'scanner' | 'collector' | (string & {})
  version?: string
  installed: boolean
  capabilities?: string[] | null
  target_types?: string[] | null
  content?:
    { name: string; version?: string; digest?: string; source?: string; managed: boolean }[] | null
  /** Absent for a tool not ported to the tool contract. */
  contract?: SensorToolContract | null
}

/** What a sensor is (RFC-033 §6.2), as the platform kept it. */
export interface SensorManifestDocument {
  schema: number
  sensor?: { name?: string; version?: string; commit?: string; build_time?: string } | null
  sdk?: { name?: string; version?: string } | null
  platform?: { os?: string; arch?: string } | null
  /** What the sensor may use (container limits when it runs in one). */
  resources?: { cpu_cores?: number; mem_total_bytes?: number } | null
  /** The operator's cap (0: none) and how slots are sized. */
  concurrency?: { ceiling: number; model?: 'dynamic' | 'fixed' | (string & {}) } | null
  /** Served whatever the tools (e.g. validate). */
  capabilities?: string[] | null
  tools: SensorManifestTool[]
}

/** An item of a manifest the platform dropped. */
export interface SensorManifestIgnored {
  path: string
  value?: string
  reason:
    | 'unknown-member'
    | 'unknown-tool'
    | 'invalid-name'
    | 'unknown-capability'
    | 'invalid-contract'
    | 'limit'
    | (string & {})
}

/** One stored version of a sensor's manifest. */
export interface SensorManifestVersion {
  digest: string
  /** sensor: the sensor registered it; heartbeat: derived from its heartbeat. */
  source: 'sensor' | 'heartbeat' | (string & {})
  current: boolean
  manifest: SensorManifestDocument
  ignored: SensorManifestIgnored[]
  first_seen_at: string
  current_since: string
  last_seen_at: string
}

export interface SensorManifestListResponse {
  items: SensorManifestVersion[]
}

/** What changed between two manifests (manifest_changed details.diff). */
export interface SensorManifestDiff {
  tools_added?: string[]
  tools_removed?: string[]
  versions?: { tool: string; from: string; to: string }[]
  installed?: { tool: string; from: string; to: string }[]
  /** Tools whose tool-contract digest changed ("" when absent). */
  contracts?: { tool: string; from: string; to: string }[]
  capabilities?: { tool?: string; added?: string[]; removed?: string[] }[]
  sensor_wide?: { added?: string[]; removed?: string[] } | null
  /** build, sdk, platform, resources, concurrency */
  other?: string[]
}

// ============================================
// SENSOR ACTIVITY (GET /api/v1/sensors/{id}/activity)
// ============================================

/** The filter chips of a sensor's activity timeline. */
export type SensorActivityCategory = 'people' | 'status' | 'updates' | 'jobs'

export const SENSOR_ACTIVITY_CATEGORIES: readonly SensorActivityCategory[] = [
  'people',
  'status',
  'updates',
  'jobs',
]

export type SensorActivityType =
  // status
  | 'online'
  | 'offline'
  | 'restarted'
  | 'heartbeat_recovered'
  // updates
  | 'version_changed'
  | 'sdk_version_changed'
  | 'protocol_changed'
  | 'tools_changed'
  | 'capacity_changed'
  | 'content_updated'
  | 'content_refresh_failed'
  | 'manifest_changed'
  | 'local_policy_changed'
  // jobs
  | 'job_claimed'
  | 'job_completed'
  | 'job_failed'
  | 'job_canceled'
  | 'job_expired'
  | 'job_refused_local_policy'
  // people (an audit-log row)
  | 'audit'
  | (string & {})

export type VersionDirection = 'upgrade' | 'downgrade' | 'changed'

/** Per-type details; every field is optional because older rows may lack them. */
export interface SensorActivityDetails {
  // restarted
  started_at?: string
  previous_started_at?: string
  downtime_seconds?: number
  // version_changed / sdk_version_changed / protocol_changed / capacity_changed
  name?: string
  from?: string | number
  to?: string | number
  direction?: VersionDirection | (string & {})
  // tools_changed
  added?: { name: string; version?: string }[]
  removed?: { name: string; version?: string }[]
  updated?: { name: string; from?: string; to?: string }[]
  // content_updated / content_refresh_failed
  items?: { tool?: string; name?: string; from?: string; to?: string; error?: string }[]
  // manifest_changed (RFC-033)
  diff?: SensorManifestDiff
  manifest_digest?: string
  previous_manifest_digest?: string
  previous_source?: string
  // online / offline
  offline_seconds?: number
  last_seen_at?: string
  // heartbeat_recovered (RFC-035): the step the sensor had reached
  was?: 'late' | 'stale' | 'offline' | (string & {})
  gap_seconds?: number
  interval_seconds?: number
  // local_policy_changed (RFC-040): from/to above are display states
  digest_from?: string
  digest_to?: string
  // job_refused_local_policy (RFC-040): the policy rule and the sensor's reason
  rule?: string
  reason?: string
  // job_*
  command_id?: string
  command_type?: string
  status?: string
  error?: string
  duration_seconds?: number
  // audit
  action?: string
  changes?: Record<string, { old?: unknown; new?: unknown }>
  message?: string
  [key: string]: unknown
}

export interface SensorActivityItem {
  /** Unique and stable ("e:<uuid>", "a:<uuid>", "j:<uuid>:done"). */
  id: string
  /** RFC3339. */
  at: string
  category: SensorActivityCategory
  type: SensorActivityType
  source: 'sensor' | 'audit' | 'job' | (string & {})
  /** Plain-English server text, the fallback for types this UI does not know. */
  summary: string
  details?: SensorActivityDetails | null
  /** >1 when identical events were coalesced. */
  repeat_count?: number
  /** The last occurrence when repeat_count > 1. */
  last_at?: string
  /** Audit rows only: the canonical action id ("sensor.updated"). */
  action?: string
  /** Audit rows only: who did it ("admin@example.com" or "system"). */
  actor?: string
  /** Audit rows only. */
  result?: 'success' | 'failure' | (string & {})
}

export interface SensorActivityResponse {
  /** Newest first. */
  items: SensorActivityItem[]
  /** "" when there is no more. */
  next_cursor: string
  /** false without audit:read: administrator actions are then left out. */
  audit_included: boolean
}

/** One 15-minute bucket of a sensor's heartbeat history (RFC-035). */
export interface SensorHeartbeatBucket {
  /** Bucket start, RFC3339 UTC. */
  at: string
  /** Heartbeats received in the bucket. */
  beats: number
  /** Average and largest time between consecutive heartbeats (0: none). */
  avg_gap_s: number
  max_gap_s: number
  /** The interval the sensor followed (what the gaps compare with). */
  interval_s: number
  /** Largest timer lag and heartbeats lost, from the sensor's control report. */
  max_lag_ms: number
  failures: number
}

/** GET /sensors/{id}/heartbeat-history: buckets that had a heartbeat, oldest first. */
export interface SensorHeartbeatHistoryResponse {
  bucket_seconds: number
  hours: number
  buckets: SensorHeartbeatBucket[]
}

export interface SensorActivityQuery {
  /** Empty = every category. */
  types?: SensorActivityCategory[]
  cursor?: string
  /** 1..100, default 30. */
  limit?: number
}

/** Display state of a sensor-local policy: paused while its kill switch is engaged. */
export type SensorLocalPolicyState = 'enforced' | 'absent' | 'paused' | 'unknown'

/** The shape of an enforced local policy (never its ranges). */
export interface SensorLocalPolicySummary {
  /** Number of allow entries; -1 when the policy sets no allow list. */
  targets_allow: number
  targets_deny: number
  allow_private: boolean
  /** Allowed ports ("" or absent = any). */
  ports?: string
  /** Allowed tools and job types (absent = any). */
  tools?: string[]
  checks?: string[]
  allow_custom_templates: boolean
  allow_interactsh: boolean
  max_rps?: number
  max_job_seconds?: number
}

/** A sensor's local policy as the API shows it (api RFC-040 §5.7). */
export interface SensorLocalPolicy {
  state: SensorLocalPolicyState | (string & {})
  source?: 'file' | 'env' | (string & {})
  digest?: string
  kill_switch: boolean
  summary?: SensorLocalPolicySummary
  warnings?: string[]
  reported_at?: string
}

// ---------------------------------------------------------------------------
// Sensor setup report (research/26 §4.4–§4.8): GET /sensors/{id}/config-report
// Hand-written to the API contract until the generated types carry it.
// ---------------------------------------------------------------------------

/** Rollup of the sensor's setup checks; "unknown" when the report is stale. */
export type SensorConfigHealth = 'ok' | 'attention' | 'impaired' | 'blocked' | 'unknown'

export type SensorConfigCheckStatus = 'pass' | 'warn' | 'fail' | 'skip' | 'error'

export type SensorConfigCheckGroup =
  | 'platform'
  | 'identity'
  | 'policy'
  | 'tools'
  | 'content'
  | 'network'
  | 'storage'
  | 'runtime'
  | 'config'
  | 'connector'

/** One setup check. `summary` and `excerpt` are the sensor's own words: data only. */
export interface SensorConfigCheck {
  id: string
  group: SensorConfigCheckGroup | (string & {})
  status: SensorConfigCheckStatus | (string & {})
  severity: 'info' | 'warning' | 'critical' | (string & {})
  code: string
  /** The platform catalog explains this check; false for a newer sensor's check. */
  known: boolean
  /** Catalog title; the id for an unknown check. */
  title: string
  /** Catalog explanation, params substituted as plain text; absent when unknown. */
  why?: string
  /** "What we saw": the typed params as label/value pairs. */
  observed?: { label: string; value: string }[]
  summary?: string
  excerpt?: string
  keys?: string[]
  blocks?: string[]
  /** Fix snippets per install format, from the platform catalog only; {} when none. */
  fix?: Partial<Record<string, string>>
  docs_url?: string
}

/** A declared setting: whether it is set and where from. Never its value. */
export interface SensorConfigSetting {
  name: string
  set: boolean
  source: 'env' | 'option' | 'default' | 'unset' | (string & {})
  secret: boolean
  valid: boolean
}

export interface SensorConfigReport {
  /** reported: sent by the sensor; derived: built by the platform from heartbeats; none: nothing yet. */
  state: 'reported' | 'derived' | 'none' | (string & {})
  /** The sensor's latest heartbeat names a different report (or none). */
  stale: boolean
  health: SensorConfigHealth | (string & {})
  observed_at?: string | null
  received_at?: string | null
  truncated: boolean
  runtime_kind?: string
  derived_note?: string
  counts?: Partial<Record<SensorConfigCheckStatus, number>>
  checks?: SensorConfigCheck[]
  settings?: SensorConfigSetting[]
}
