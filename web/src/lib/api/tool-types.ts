/**
 * Tool Registry API Types
 *
 * TypeScript types for Tool Registry Management
 */

// Tool categories
export const TOOL_CATEGORIES = [
  'sast', // Static Application Security Testing
  'sca', // Software Composition Analysis
  'dast', // Dynamic Application Security Testing
  'secrets', // Secret Detection
  'iac', // Infrastructure as Code
  'container', // Container Security
  'recon', // Reconnaissance
  'osint', // Open Source Intelligence
] as const

export type ToolCategory = (typeof TOOL_CATEGORIES)[number]

// Install methods
export const INSTALL_METHODS = ['go', 'pip', 'npm', 'docker', 'binary'] as const

export type InstallMethod = (typeof INSTALL_METHODS)[number]

// Execution status for tool executions
export const EXECUTION_STATUSES = ['running', 'completed', 'failed', 'timeout'] as const

export type ExecutionStatus = (typeof EXECUTION_STATUSES)[number]

/**
 * Embedded category info for tool grouping in UI
 */
export interface EmbeddedCategory {
  id: string
  name: string // slug: 'sast', 'dast', etc.
  display_name: string // 'SAST', 'DAST', etc.
  icon: string
  color: string
}

/**
 * Tool entity - System-wide tool definition
 */
export interface Tool {
  id: string
  tenant_id?: string // null for platform tools, UUID for custom tools
  name: string
  display_name: string
  description?: string
  logo_url?: string
  category_id?: string // Foreign key to tool_categories table
  category?: EmbeddedCategory // Embedded category info for UI grouping
  install_method: InstallMethod
  install_cmd?: string
  update_cmd?: string
  version_cmd?: string
  version_regex?: string
  /** Oldest version the catalog accepts (a release version; empty: none). */
  min_version?: string
  current_version?: string
  latest_version?: string
  has_update: boolean
  config_file_path?: string
  config_schema?: Record<string, unknown>
  default_config?: Record<string, unknown>
  capabilities: string[]
  supported_targets: string[]
  output_formats: string[]
  docs_url?: string
  github_url?: string
  is_active: boolean
  is_builtin: boolean
  is_platform_tool: boolean // true for platform tools, false for custom tools
  tags: string[]
  metadata?: Record<string, unknown>
  created_by?: string // User ID who created the tool (for custom tools)
  created_at: string
  updated_at: string
}

/**
 * Create tool request
 */
export interface CreateToolRequest {
  name: string
  display_name?: string
  description?: string
  category_id?: string // UUID reference to tool_categories table
  install_method: InstallMethod
  install_cmd?: string
  update_cmd?: string
  version_cmd?: string
  version_regex?: string
  /** Oldest version the catalog accepts (a release version; empty: none). */
  min_version?: string
  config_schema?: Record<string, unknown>
  default_config?: Record<string, unknown>
  capabilities?: string[]
  supported_targets?: string[]
  output_formats?: string[]
  docs_url?: string
  github_url?: string
  logo_url?: string
  tags?: string[]
}

/**
 * Update tool request
 */
export interface UpdateToolRequest {
  display_name?: string
  description?: string
  category_id?: string // Optional: link to tool_categories table
  install_cmd?: string
  update_cmd?: string
  version_cmd?: string
  version_regex?: string
  /** Oldest version the catalog accepts (a release version; empty: none). */
  min_version?: string
  config_schema?: Record<string, unknown>
  default_config?: Record<string, unknown>
  capabilities?: string[]
  supported_targets?: string[]
  output_formats?: string[]
  docs_url?: string
  github_url?: string
  logo_url?: string
  tags?: string[]
}

/** Settings, availability and run statistics a tool read can include. */
export type ToolInclude = 'settings' | 'availability' | 'stats'

/**
 * Tool list filters (GET /api/v1/tools). include values need
 * scans:tenant_tools:read; one the caller may not read is left out and named
 * in meta.omitted_includes. per_page is capped at 100, and at 50 with
 * availability or stats.
 */
export interface ToolListFilters {
  source?: 'platform' | 'custom'
  category?: string
  q?: string
  /** Active in the catalog and switched on for the organization. */
  enabled?: boolean
  /** A scan job can be dispatched now. */
  available?: boolean
  zone_id?: string
  /** Comma-separated ToolInclude values (at most 3). */
  include?: string
  days?: number
  sort?: string
  page?: number
  per_page?: number
}

/**
 * Custom template for tenant tool config
 */
export interface CustomTemplate {
  name: string
  path?: string
  content?: string
}

/**
 * Custom pattern for tenant tool config
 */
export interface CustomPattern {
  name: string
  pattern: string
}

/** The organization's settings of one tool (include=settings). */
export interface ToolSettings {
  is_enabled: boolean
  /** The organization's overrides (credential-like values masked). */
  config: Record<string, unknown>
  effective_config: Record<string, unknown>
  custom_templates?: CustomTemplate[]
  custom_patterns?: CustomPattern[]
  updated_by?: string
  updated_at?: string
}

/** PATCH /api/v1/tools/{id}/settings: an omitted field is left as it is. */
export interface ToolSettingsRequest {
  is_enabled?: boolean
  /** {} clears the overrides. */
  config?: Record<string, unknown>
}

/** PATCH /api/v1/tools/settings */
export interface BulkToolSettingsRequest {
  tool_ids: string[]
  is_enabled: boolean
}

/** Tool run statistics (include=stats). */
export interface ToolStats {
  tool_id: string
  total_runs: number
  successful_runs: number
  failed_runs: number
  total_findings: number
  avg_duration_ms: number
}

/** One tool of the organization's view of the catalog. */
export interface ToolView extends Tool {
  source: 'platform' | 'custom'
  settings?: ToolSettings
  availability?: ToolAvailabilityInfo
  stats?: ToolStats
}

export interface IncludeMeta {
  omitted_includes: string[]
}

/** GET /api/v1/tools */
export interface ToolListResponse {
  items: ToolView[]
  total: number
  page: number
  per_page: number
  total_pages: number
  /** include=availability: the whole view's summary and the unlisted tools. */
  availability?: {
    summary: Record<ToolAvailabilityStatus, number>
    zone_id?: string
    computed_at: string
    unlisted: (ToolAvailabilityInfo & { name: string })[]
  }
  meta: IncludeMeta
}

/**
 * A tool with the organization's settings, as the workflow pickers read it
 * (built from GET /api/v1/tools?include=settings,availability).
 */
export interface ToolWithConfig {
  tool: ToolView
  effective_config: Record<string, unknown>
  /** The organization's switch; null when the settings were left out (unknown, never assumed on). */
  is_enabled: boolean | null
  /** A scan job for the tool can be dispatched now; null when unknown. */
  is_available: boolean | null
}

export interface ToolsWithConfigListResponse {
  items: ToolWithConfig[]
  total: number
}

// Helper to get category display name
export const CATEGORY_DISPLAY_NAMES: Record<ToolCategory, string> = {
  sast: 'SAST',
  sca: 'SCA',
  dast: 'DAST',
  secrets: 'Secrets',
  iac: 'IaC',
  container: 'Container',
  recon: 'Recon',
  osint: 'OSINT',
}

// Helper to get install method display name
export const INSTALL_METHOD_DISPLAY_NAMES: Record<InstallMethod, string> = {
  go: 'Go Install',
  pip: 'Pip Install',
  npm: 'NPM Install',
  docker: 'Docker Pull',
  binary: 'Binary Download',
}

// ============================================
// TOOL AVAILABILITY (GET /api/v1/tools?include=availability)
// api/docs/architecture/tool-availability.md
// ============================================

/** A tool's availability for the organization, derived by the API. */
export type ToolAvailabilityStatus =
  'ready' | 'no_sensor' | 'offline_only' | 'outdated' | 'disabled'

/** One sensor that reports a tool installed. */
export interface ToolAvailabilitySensor {
  id: string
  name: string
  /** The sensor's state as the Sensors page shows it. */
  state: string
  /** The sensor takes work now. */
  online: boolean
  zones: { id: string; name: string }[]
  version?: string
  content?: { name: string; version?: string; updated_at?: string }[]
  /** Why the sensor may not run the tool although it has it. */
  excluded?: 'grant' | 'local_policy'
  excluded_detail?: string
  /** The tool's trust on this sensor; absent when it reports no tool contract. */
  trust?: ToolTrust
  /** The tier the platform assigns a scan with the tool on this sensor. */
  tier?: ToolTier
}

/** builtin: compiled into the sensor; unverified: installed by its operator (runs only as T2). */
export type ToolTrust = 'builtin' | 'unverified'

/** T0 passive, T1 active, T2 intrusive (RFC-055 §5). */
export type ToolTier = 'T0' | 'T1' | 'T2'

/** One tool's availability from the organization's sensors (include=availability). */
export interface ToolAvailabilityInfo {
  /** Active in the catalog and switched on for the organization. */
  enabled: boolean
  status: ToolAvailabilityStatus
  /** Sensors that may run the tool, and how many of them take work now. */
  sensors_online: number
  sensors_total: number
  /** Sensors that have the tool but may not run it. */
  sensors_excluded: number
  /** Empty without sensors:read (the counts are always given). */
  sensors: ToolAvailabilitySensor[]
  versions: string[]
  min_reported_version?: string
  max_reported_version?: string
  min_version?: string
  latest_version?: string
  update_available: boolean
  content: { name: string; versions: string[] }[]
  last_reported_at?: string
  /** The lowest trust among the sensors that can run the tool; absent when none reports a contract. */
  trust?: ToolTrust
  /** The highest tier the platform assigns a scan with the tool on those sensors. */
  tier?: ToolTier
}

/** One tool of the availability view: a catalog tool or one only the sensors report. */
export interface ToolAvailabilityItem extends ToolAvailabilityInfo {
  name: string
  /** The catalog entry; null for a tool a sensor reports that the catalog does not list. */
  tool: ToolView | null
  in_catalog: boolean
}

/** The availability view as the Tools page and the pickers read it. */
export interface ToolAvailabilityResponse {
  items: ToolAvailabilityItem[]
  summary: Record<ToolAvailabilityStatus, number>
  zone_id?: string
  computed_at: string
}
