/**
 * Exposure Event API Types
 *
 * TypeScript types for Exposure Event Management (Attack Surface Monitoring)
 * Exposures track non-CVE attack surface changes like port opens, misconfigs, etc.
 */

import { SEVERITY_BADGE_LIGHT } from '@/lib/severity-colors'

// Exposure event types - categories of attack surface changes
export type ExposureEventType =
  | 'port_open'
  | 'port_closed'
  | 'service_detected'
  | 'service_changed'
  | 'subdomain_discovered'
  | 'subdomain_removed'
  | 'certificate_expiring'
  | 'certificate_expired'
  | 'bucket_public'
  | 'bucket_private'
  | 'repo_public'
  | 'repo_private'
  | 'api_exposed'
  | 'api_removed'
  | 'credential_leaked'
  | 'sensitive_data_exposed'
  | 'misconfiguration'
  | 'dns_change'
  | 'ssl_issue'
  | 'header_missing'
  | 'dangling_cname'
  | 'dangling_ns'
  | 'email_security_weak'
  | 'subdomain_takeover'
  | 'lookalike_domain'
  | 'third_party_script_added'
  | 'identity_mfa_gap'
  | 'identity_stale_principal'
  | 'identity_overprivileged'
  | 'web_interface_exposed'
  | 'mcp_server_exposed'
  | 'mail_server_blocklisted'
  | 'custom'

// Exposure severity levels
export type ExposureSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

// Exposure state - lifecycle management
export type ExposureState = 'active' | 'in_progress' | 'resolved' | 'accepted' | 'false_positive'

/** The states of an exposure that still needs work. */
export const OPEN_EXPOSURE_STATES: ExposureState[] = ['active', 'in_progress']

/**
 * Display categories, one per event type, in presentation order (the API's
 * exposure.Categories()). `produced`: the platform ships a producer for the
 * category today; a category without one is shown only when it has
 * exposures.
 */
export const EXPOSURE_DISPLAY_CATEGORIES = [
  { key: 'exposed_ports', label: 'Exposed ports', produced: true },
  { key: 'web_interfaces', label: 'Exposed web interfaces', produced: false },
  { key: 'exposed_apis', label: 'Exposed APIs', produced: true },
  { key: 'ai_services', label: 'Exposed AI services', produced: false },
  { key: 'web_application', label: 'Web application security', produced: true },
  { key: 'ssl_tls', label: 'SSL/TLS issues', produced: true },
  { key: 'certificates', label: 'Certificates', produced: true },
  { key: 'hijackable_subdomains', label: 'Hijackable subdomains', produced: true },
  { key: 'email_security', label: 'Email security', produced: true },
  { key: 'cloud_storage', label: 'Exposed cloud storage', produced: false },
  { key: 'code_repositories', label: 'Public code repositories', produced: false },
  { key: 'credentials_data', label: 'Leaked credentials and data', produced: true },
  { key: 'dns', label: 'DNS changes', produced: true },
  { key: 'lookalike_domains', label: 'Lookalike domains', produced: true },
  { key: 'identity', label: 'Identity', produced: true },
  { key: 'other', label: 'Other', produced: true },
] as const

export type ExposureDisplayCategory = (typeof EXPOSURE_DISPLAY_CATEGORIES)[number]['key']

export function isExposureDisplayCategory(v: string): v is ExposureDisplayCategory {
  return EXPOSURE_DISPLAY_CATEGORIES.some((c) => c.key === v)
}

/**
 * One-line description of an exposure: the English sentence, the sentence
 * form used (variant) and its values, so the web renders the same sentence
 * in the viewer's language. Scan output: render as text.
 */
export interface ExposureSummary {
  text: string
  variant?: string
  args?: Record<string, string>
}

/** A standing analyst override of an exposure's severity. */
export interface ExposureSeverityOverride {
  /** What the producer reported (and keeps reporting). */
  reported_severity: ExposureSeverity
  reason: string
  overridden_by?: string
  overridden_at?: string
}

/**
 * Exposure Event entity from API
 */
/**
 * An accept or false-positive request on a high or critical exposure that
 * waits for a second approver (four-eyes). `requested_by` is a user id.
 */
export interface PendingDisposition {
  id: string
  requested_state: 'accepted' | 'false_positive'
  requested_by?: string
  reason: string
  created_at: string
  /**
   * Set on the viewer's own request when they may approve it themselves: an
   * owner with no other approver, with a reason and a fresh authenticator code.
   */
  self_approval_available?: boolean
}

export interface ExposureEvent {
  id: string
  /** Present while a disposition waits for a second approver. */
  pending_disposition?: PendingDisposition
  canonical_asset_id?: string
  native_asset_id?: string
  event_type: ExposureEventType
  display_category?: ExposureDisplayCategory
  summary?: ExposureSummary
  /** The effective severity (an analyst's override when one stands). */
  severity: ExposureSeverity
  severity_override?: ExposureSeverityOverride
  state: ExposureState
  title: string
  description?: string
  details?: Record<string, unknown>
  fingerprint: string
  source: string
  first_seen_at: string
  last_seen_at: string
  resolved_at?: string
  resolved_by?: string
  resolution_notes?: string
  created_at: string
  updated_at: string

  // CTEM enrichment (read-time, additive — api #483). Present only when the
  // server-side enricher is wired AND the exposure has a linked asset
  // (effective_criticality / reachability) or a CVE in its details (EPSS / KEV).
  // Every field is optional: an exposure with no asset or no CVE carries fewer
  // signals. Field names mirror the ExposureResponse JSON and the finding-side
  // threat signals so the UX stays coherent across features.
  /** MAX(asset own, business unit, powered services) — business-aligned criticality. */
  effective_criticality?: string
  /** Linked asset is public-facing OR sits on a validated public→crown-jewel path. */
  is_internet_accessible?: boolean
  /** Linked asset sits on a validated attack path to a KEV / crown-jewel target. */
  on_attack_path?: boolean
  /** CVE id resolved from the exposure's details (only when one is present). */
  cve_id?: string
  /** EPSS probability of exploitation in the next 30 days (0..1). */
  epss_score?: number
  /** EPSS percentile rank (0..100). */
  epss_percentile?: number
  /** CVE is in the CISA Known Exploited Vulnerabilities catalog. */
  is_in_kev?: boolean
  /** CISA KEV remediation due date (ISO 8601). */
  kev_due_date?: string
}

/**
 * User info for state history attribution
 */
export interface StateHistoryUser {
  id: string
  name: string
  email: string
  avatar_url?: string
}

/**
 * State history entry - audit trail for state changes
 */
export interface ExposureStateHistory {
  id: string
  previous_state: ExposureState
  new_state: ExposureState
  changed_by?: string
  changed_by_user?: StateHistoryUser
  reason?: string
  created_at: string
}

/**
 * Exposure list filters
 */
export interface ExposureListFilters {
  canonical_asset_id?: string
  native_asset_id?: string
  event_types?: ExposureEventType[]
  severities?: ExposureSeverity[]
  states?: ExposureState[]
  sources?: string[]
  categories?: ExposureDisplayCategory[]
  search?: string
  first_seen_after?: number // Unix timestamp
  first_seen_before?: number // Unix timestamp
  last_seen_after?: number // Unix timestamp
  last_seen_before?: number // Unix timestamp
  page?: number
  per_page?: number
  sort_by?: string
  sort_order?: 'asc' | 'desc'
}

/**
 * Paginated list response
 */
export interface ExposureListResponse {
  data: ExposureEvent[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

/**
 * Create exposure event request
 */
export interface CreateExposureRequest {
  canonical_asset_id?: string
  native_asset_id?: string
  event_type: ExposureEventType
  severity: ExposureSeverity
  title: string
  description?: string
  source: string
  details?: Record<string, unknown>
}

/**
 * Bulk ingest request
 */
export interface BulkIngestExposuresRequest {
  exposures: CreateExposureRequest[]
}

/**
 * Bulk ingest response
 */
export interface BulkIngestExposuresResponse {
  ingested: number
  items: ExposureEvent[]
}

/**
 * Change state request (resolve, accept, false-positive)
 */
export interface ChangeExposureStateRequest {
  reason?: string
  /** The owner approves their own pending request (no other approver). */
  self_approve?: boolean
  /** Fresh code from the owner's authenticator app (with self_approve). */
  totp_code?: string
}

/**
 * State history response
 */
export interface ExposureStateHistoryResponse {
  items: ExposureStateHistory[]
  total: number
}

/**
 * Exposure statistics
 */
export interface ExposureStats {
  total: number
  by_severity: Record<ExposureSeverity, number>
  by_state: Record<ExposureState, number>
  by_event_type: Record<string, number>
  by_category?: Partial<Record<ExposureDisplayCategory, number>>
  /** Every open exposure (active or in progress). */
  active_count: number
  in_progress_count?: number
  resolved_count: number
  mttr_hours?: number // Mean Time To Resolve
}

/**
 * Event type configuration for UI display
 */
export const EVENT_TYPE_CONFIG: Record<
  ExposureEventType,
  { label: string; description: string; category: string }
> = {
  port_open: {
    label: 'Port Open',
    description: 'New port opened on host',
    category: 'network',
  },
  port_closed: {
    label: 'Port Closed',
    description: 'Port was closed on host',
    category: 'network',
  },
  service_detected: {
    label: 'Service Detected',
    description: 'New service detected running',
    category: 'service',
  },
  service_changed: {
    label: 'Service Changed',
    description: 'Service version or config changed',
    category: 'service',
  },
  subdomain_discovered: {
    label: 'Subdomain Discovered',
    description: 'New subdomain found',
    category: 'domain',
  },
  subdomain_removed: {
    label: 'Subdomain Removed',
    description: 'Subdomain no longer resolves',
    category: 'domain',
  },
  certificate_expiring: {
    label: 'Certificate Expiring',
    description: 'SSL certificate expiring soon',
    category: 'certificate',
  },
  certificate_expired: {
    label: 'Certificate Expired',
    description: 'SSL certificate has expired',
    category: 'certificate',
  },
  bucket_public: {
    label: 'Bucket Public',
    description: 'Storage bucket is publicly accessible',
    category: 'cloud',
  },
  bucket_private: {
    label: 'Bucket Private',
    description: 'Storage bucket access restricted',
    category: 'cloud',
  },
  repo_public: {
    label: 'Repository Public',
    description: 'Code repository is public',
    category: 'code',
  },
  repo_private: {
    label: 'Repository Private',
    description: 'Code repository made private',
    category: 'code',
  },
  api_exposed: {
    label: 'API Exposed',
    description: 'API endpoint publicly accessible',
    category: 'api',
  },
  api_removed: {
    label: 'API Removed',
    description: 'API endpoint no longer accessible',
    category: 'api',
  },
  credential_leaked: {
    label: 'Credential Leaked',
    description: 'Credentials found in public source',
    category: 'credential',
  },
  sensitive_data_exposed: {
    label: 'Sensitive Data Exposed',
    description: 'Sensitive data publicly accessible',
    category: 'data',
  },
  misconfiguration: {
    label: 'Misconfiguration',
    description: 'Security misconfiguration detected',
    category: 'config',
  },
  dns_change: {
    label: 'DNS Change',
    description: 'A DNS record of the host changed',
    category: 'domain',
  },
  ssl_issue: {
    label: 'TLS Issue',
    description: 'Weak or broken TLS configuration',
    category: 'certificate',
  },
  header_missing: {
    label: 'Security Header Missing',
    description: 'An HTTP security header is missing',
    category: 'config',
  },
  dangling_cname: {
    label: 'Dangling CNAME',
    description: 'A CNAME points to a name that no longer exists (takeover risk)',
    category: 'domain',
  },
  dangling_ns: {
    label: 'Dangling Delegation',
    description: 'A delegation points to name servers that do not exist',
    category: 'domain',
  },
  email_security_weak: {
    label: 'Weak Email Security',
    description: 'SPF, DMARC, MTA-STS or TLS-RPT is missing or weak',
    category: 'domain',
  },
  subdomain_takeover: {
    label: 'Subdomain Takeover',
    description: 'A takeover check confirmed the name can be claimed',
    category: 'domain',
  },
  lookalike_domain: {
    label: 'Lookalike Domain',
    description: 'A registered domain that imitates one of your root domains',
    category: 'domain',
  },
  third_party_script_added: {
    label: 'New Third-Party Script',
    description: 'A watched page started loading a script from a host it did not use before',
    category: 'domain',
  },
  identity_mfa_gap: {
    label: 'MFA Gap',
    description: 'An identity without multi-factor authentication',
    category: 'identity',
  },
  identity_stale_principal: {
    label: 'Stale Identity',
    description: 'An identity unused for a long time',
    category: 'identity',
  },
  identity_overprivileged: {
    label: 'Over-privileged Identity',
    description: 'An identity with more rights than it uses',
    category: 'identity',
  },
  web_interface_exposed: {
    label: 'Web Interface Exposed',
    description: 'A login or administration page reachable from the internet',
    category: 'config',
  },
  mcp_server_exposed: {
    label: 'MCP Server Exposed',
    description: 'A Model Context Protocol server reachable from the internet',
    category: 'service',
  },
  mail_server_blocklisted: {
    label: 'Mail Server Blocklisted',
    description: 'A mail server address listed on a DNS blocklist',
    category: 'domain',
  },
  custom: {
    label: 'Custom',
    description: 'Custom exposure event',
    category: 'other',
  },
}

/**
 * Split a centralized light-pill palette entry into the `color` (text) and
 * `bgColor` fields this config exposes, so severity colors stay sourced from
 * `@/lib/severity-colors` (`ExposureSeverity` shares the palette's key set).
 */
function lightSeverityStyles(level: ExposureSeverity): { color: string; bgColor: string } {
  const tokens = SEVERITY_BADGE_LIGHT[level].split(' ')
  const pick = (...prefixes: string[]): string =>
    tokens.filter((t) => prefixes.some((p) => t.startsWith(p))).join(' ')
  return {
    color: pick('text-', 'dark:text-'),
    bgColor: pick('bg-', 'dark:bg-'),
  }
}

/**
 * Severity configuration for UI display
 */
export const EXPOSURE_SEVERITY_CONFIG: Record<
  ExposureSeverity,
  { label: string; color: string; bgColor: string }
> = {
  critical: { label: 'Critical', ...lightSeverityStyles('critical') },
  high: { label: 'High', ...lightSeverityStyles('high') },
  medium: { label: 'Medium', ...lightSeverityStyles('medium') },
  low: { label: 'Low', ...lightSeverityStyles('low') },
  info: { label: 'Info', ...lightSeverityStyles('info') },
}

/**
 * State configuration for UI display
 */
export const EXPOSURE_STATE_CONFIG: Record<
  ExposureState,
  { label: string; color: string; bgColor: string }
> = {
  active: {
    label: 'Active',
    color: 'text-red-600',
    bgColor: 'bg-red-100 dark:bg-red-900/30',
  },
  in_progress: {
    label: 'In progress',
    color: 'text-blue-600', // palette-ok: distinct state accent, matches its siblings
    bgColor: 'bg-blue-100 dark:bg-blue-900/30', // palette-ok: distinct state accent
  },
  resolved: {
    label: 'Resolved',
    color: 'text-green-600',
    bgColor: 'bg-green-100 dark:bg-green-900/30',
  },
  accepted: {
    label: 'Accepted',
    color: 'text-yellow-600',
    bgColor: 'bg-yellow-100 dark:bg-yellow-900/30',
  },
  false_positive: {
    label: 'False Positive',
    color: 'text-gray-600',
    bgColor: 'bg-gray-100 dark:bg-gray-900/30',
  },
}

/**
 * Event category configuration for grouping in UI
 */
export const EVENT_CATEGORY_CONFIG: Record<
  string,
  { label: string; icon: string; events: ExposureEventType[] }
> = {
  network: {
    label: 'Network',
    icon: 'network',
    events: ['port_open', 'port_closed'],
  },
  service: {
    label: 'Services',
    icon: 'server',
    events: ['service_detected', 'service_changed'],
  },
  domain: {
    label: 'Domains',
    icon: 'globe',
    events: ['subdomain_discovered', 'subdomain_removed'],
  },
  certificate: {
    label: 'Certificates',
    icon: 'shield-check',
    events: ['certificate_expiring', 'certificate_expired'],
  },
  cloud: {
    label: 'Cloud',
    icon: 'cloud',
    events: ['bucket_public', 'bucket_private'],
  },
  code: {
    label: 'Code',
    icon: 'code',
    events: ['repo_public', 'repo_private'],
  },
  api: {
    label: 'APIs',
    icon: 'plug',
    events: ['api_exposed', 'api_removed'],
  },
  credential: {
    label: 'Credentials',
    icon: 'key',
    events: ['credential_leaked'],
  },
  data: {
    label: 'Data',
    icon: 'database',
    events: ['sensitive_data_exposed'],
  },
  config: {
    label: 'Configuration',
    icon: 'settings',
    events: ['misconfiguration'],
  },
  other: {
    label: 'Other',
    icon: 'help-circle',
    events: ['custom'],
  },
}
