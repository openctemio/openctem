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
}

/**
 * Input for updating a scope target
 */
export interface UpdateScopeTargetInput {
  description?: string
  status?: string
  priority?: number
  tags?: string[]
}

/**
 * Input for creating a scope exclusion
 */
export interface CreateScopeExclusionInput {
  exclusion_type: string
  pattern: string
  reason: string
  expires_at?: string
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
