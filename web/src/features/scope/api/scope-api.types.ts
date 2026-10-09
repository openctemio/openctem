/**
 * Scope Configuration API Types
 *
 * Type definitions matching backend API responses for scope configuration
 * Following CTEM (Continuous Threat Exposure Management) Scoping phase
 *
 * The response shapes are GENERATED from the API's OpenAPI spec; only the
 * request inputs and query filters are declared here.
 */
import type {
  ApiResponse,
  Schemas,
  ScopeBulkOperationResponse,
  ScopeExclusionResponse,
  CheckScopeResponse,
  ScopeStatsResponse,
  ScopeTargetResponse,
} from '@/lib/api/generated'

// Types imported from '../types' are used for reference only - actual API values are strings

// ============================================
// Common Types
// ============================================

// Note: These are used for frontend display; actual values come from backend as strings

// ============================================
// API Response Types — GENERATED
//
// Aliases into src/lib/api/generated; nothing here restates a field. The list
// envelopes and PaginationLinks are named schemas on the server, so they are
// aliased rather than re-declared.
// ============================================

export type ApiScopeTarget = ScopeTargetResponse
export type ApiScopeExclusion = ScopeExclusionResponse
export type ApiScopeStats = ScopeStatsResponse
// POST /scope/check is a dry run of the active-probe gate (RFC-054 §6.4).
export type ApiCheckScopeResponse = CheckScopeResponse
export type BulkOperationResponse = ScopeBulkOperationResponse

export type PaginationLinks = Schemas['internal_infra_http_handler.PaginationLinks']

export type ApiScopeTargetListResponse = ApiResponse<'/scope/targets', 'get'>
export type ApiScopeExclusionListResponse = ApiResponse<'/scope/exclusions', 'get'>

/**
 * Input for checking if a value is in scope
 */
export interface CheckScopeInput {
  targets: string[]
  sensor_preference?: 'auto' | 'tenant' | 'platform'
  tier?: 0 | 1 | 2
  /** Without tier: check at the tier a scan with this scanner probes at (server-side). */
  scanner_name?: string
}

// ============================================
// Input Types
// ============================================

/**
 * Input for creating a new scope target
 */
export interface CreateScopeTargetInput {
  target_type: string
  pattern: string
  description?: string
  priority?: number
  tags?: string[]
  /** Authority statement; required for one-off entries, requests and t2. */
  reason?: string
  /** 1..one_off_max_days: makes the entry a one-off that expires. */
  expires_in_days?: number
  /** Probe ceiling; the organization's default_max_tier when omitted. */
  max_tier?: ScopeTier
}

/** Probe tiers (RFC-036): t0 passive, t1 safe active, t2 intrusive. */
export type ScopeTier = 't0' | 't1' | 't2'

/**
 * Input for updating a scope target. A later or removed expiry, or a higher
 * tier, widens the entry (approver + step-up; it may go back to pending).
 */
export interface UpdateScopeTargetInput {
  description?: string
  priority?: number
  tags?: string[]
  reason?: string
  expires_in_days?: number
  clear_expiry?: boolean
  max_tier?: ScopeTier
}

/** GET/PUT /scope/settings (RFC-054 §6.3). */
export type ApiScopeSettings = Schemas['internal_infra_http_handler.ScopeSettingsResponse']

export type ScopeOneOffPolicy = 'admins' | 'admins_and_requests' | 'disabled'

/** The longest an intrusive (t2) entry may last (owner-only, RFC-054 §12.4). */
export type ScopeT2MaxDuration = '7d' | '30d' | '90d' | '365d' | 'permanent'

export interface UpdateScopeSettingsInput {
  auto_join_discovered: boolean
  one_off_targets: ScopeOneOffPolicy
  one_off_max_days: number
  /** null: the default min(1, admins - 1). */
  widening_approvals: number | null
  default_max_tier: 't0' | 't1'
}

/** One result of POST /scope/check. */
export type ApiScopeCheckResult = Schemas['internal_infra_http_handler.ScopeCheckResult']
/** A fix the API offers for a refused target (RFC-054 §6.5). */
export type ApiScopeFix = Schemas['github_com_openctemio_openctem_api_pkg_domain_scope.Fix']

/**
 * Input for creating a scope exclusion
 */
export interface CreateScopeExclusionInput {
  exclusion_type: string
  pattern: string
  reason: string
  expires_at?: string
  /** `path` exclusions (RFC-056): the pattern is a host pattern. */
  path_prefix?: string
  /** Methods the path rule blocks; empty blocks every method. */
  methods?: string[]
}

/**
 * How a path exclusion may be tested (RFC-056 §5, RFC-054 §6.2):
 * blocked (nothing is sent), read_only (GET and HEAD), allowed (in scope
 * until testing_until).
 */
export type ExclusionTesting = 'blocked' | 'read_only' | 'allowed'

/**
 * The path-exclusion fields of an exclusion response. Declared here until
 * the generated contract carries them (they arrive with the API's path
 * exclusions, #1326).
 */
export interface PathExclusionFields {
  host_pattern?: string
  path_prefix?: string
  methods?: string[]
  testing?: ExclusionTesting
  testing_effective?: ExclusionTesting
  testing_until?: string
  testing_changed_by?: string
  testing_changed_at?: string
}

/** PUT /scope/exclusions/{id}/testing */
export interface SetExclusionTestingInput {
  testing: ExclusionTesting
  testing_until?: string
}

/**
 * Input for updating a scope exclusion
 */
export interface UpdateScopeExclusionInput {
  reason?: string
  status?: string
  expires_at?: string
}

// ============================================
// Filter Types
// ============================================

export interface ScopeTargetFilters {
  target_type?: string
  status?: string
  search?: string
  page?: number
  per_page?: number
  sort_by?: 'created_at' | 'updated_at' | 'pattern' | 'target_type'
  sort_order?: 'asc' | 'desc'
}

export interface ScopeExclusionFilters {
  exclusion_type?: string
  status?: string
  search?: string
  page?: number
  per_page?: number
  sort_by?: 'created_at' | 'updated_at' | 'pattern' | 'exclusion_type'
  sort_order?: 'asc' | 'desc'
}

// ============================================
// Bulk Operation Types
// ============================================

export interface BulkDeleteTargetsInput {
  target_ids: string[]
}

export interface BulkDeleteExclusionsInput {
  exclusion_ids: string[]
}

export interface BulkUpdateTargetsInput {
  target_ids: string[]
  update: {
    status?: string
    priority?: number
    add_tags?: string[]
    remove_tags?: string[]
  }
}
