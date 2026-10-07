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

/**
 * Tool list response
 */
export interface ToolListResponse {
  items: Tool[]
  total: number
  page: number
  per_page: number
}

/**
 * Tool list filters
 */
export interface ToolListFilters {
  category?: ToolCategory
  capabilities?: string[]
  is_active?: boolean
  is_builtin?: boolean
  search?: string
  tags?: string[]
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

/**
 * Tenant Tool Config - Tenant-specific tool configuration
 */
export interface TenantToolConfig {
  id: string
  tenant_id: string
  tool_id: string
  config: Record<string, unknown>
  custom_templates?: CustomTemplate[]
  custom_patterns?: CustomPattern[]
  is_enabled: boolean
  updated_by?: string
  created_at: string
  updated_at: string
}

/**
 * Create/Update tenant tool config request
 */
export interface TenantToolConfigRequest {
  config?: Record<string, unknown>
  is_enabled: boolean
}

/**
 * Tenant tool config list response
 */
export interface TenantToolConfigListResponse {
  items: TenantToolConfig[]
  total: number
  page: number
  per_page: number
}

/**
 * Tenant tool config list filters
 */
export interface TenantToolConfigListFilters {
  tool_id?: string
  is_enabled?: boolean
  page?: number
  per_page?: number
}

/**
 * Tool with tenant config
 */
export interface ToolWithConfig {
  tool: Tool
  tenant_config?: TenantToolConfig
  effective_config: Record<string, unknown>
  is_enabled: boolean
  is_available: boolean // True if at least one sensor (tenant or platform) supports this tool
}

/**
 * Tools with config list response (from /tenant-tools/all-tools)
 */
export interface ToolsWithConfigListResponse {
  items: ToolWithConfig[]
  total: number
  page: number
  per_page: number
}

/**
 * Bulk tool IDs request
 */
export interface BulkToolIDsRequest {
  tool_ids: string[]
}

/**
 * Tool stats
 */
export interface ToolStats {
  tool_id: string
  total_runs: number
  successful_runs: number
  failed_runs: number
  total_findings: number
  avg_duration_ms: number
}

/**
 * Tenant tool stats
 */
export interface TenantToolStats {
  tenant_id: string
  total_runs: number
  successful_runs: number
  failed_runs: number
  total_findings: number
  tool_breakdown: ToolStats[]
}

/**
 * Tool execution
 */
export interface ToolExecution {
  id: string
  tenant_id: string
  tool_id: string
  sensor_id?: string
  pipeline_run_id?: string
  step_run_id?: string
  status: ExecutionStatus
  input_config?: Record<string, unknown>
  targets_count: number
  findings_count: number
  output_summary?: Record<string, unknown>
  error_message?: string
  started_at: string
  completed_at?: string
  duration_ms: number
  created_at: string
}

/**
 * Tool execution list response
 */
export interface ToolExecutionListResponse {
  items: ToolExecution[]
  total: number
  page: number
  per_page: number
}

/**
 * Tool execution list filters
 */
export interface ToolExecutionListFilters {
  tool_id?: string
  sensor_id?: string
  pipeline_run_id?: string
  status?: ExecutionStatus
  page?: number
  per_page?: number
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
// TOOL AVAILABILITY (GET /api/v1/tenant-tools/availability)
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
}

/** One tool of the availability view. */
export interface ToolAvailabilityItem {
  name: string
  /** The catalog entry; null for a tool a sensor reports that the catalog does not list. */
  tool: Tool | null
  in_catalog: boolean
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
}

export interface ToolAvailabilityResponse {
  items: ToolAvailabilityItem[]
  summary: Record<ToolAvailabilityStatus, number>
  zone_id?: string
  computed_at: string
}
