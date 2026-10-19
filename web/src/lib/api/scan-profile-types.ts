/**
 * Scan Profile API Types
 *
 * TypeScript types for Scan Profile Management
 */

/**
 * Quality Gate configuration for CI/CD pass/fail decisions
 */
export interface QualityGate {
  enabled: boolean
  fail_on_critical: boolean
  fail_on_high: boolean
  max_critical: number // -1 = unlimited
  max_high: number
  max_medium: number
  max_total: number
  new_findings_only?: boolean
  baseline_branch?: string
}

/**
 * Quality Gate breach when threshold is exceeded
 */
export interface QualityGateBreach {
  metric: 'critical' | 'high' | 'medium' | 'total'
  limit: number
  actual: number
}

/**
 * Finding counts by severity
 */
export interface FindingCounts {
  critical: number
  high: number
  medium: number
  low: number
  info: number
  total: number
}

/**
 * Quality Gate evaluation result
 */
export interface QualityGateResult {
  passed: boolean
  reason?: string
  breaches?: QualityGateBreach[]
  counts: FindingCounts
}

/**
 * Scan Profile entity
 */
export interface ScanProfile {
  id: string
  tenant_id: string
  name: string
  description?: string
  is_default: boolean
  is_system: boolean
  tags: string[]
  metadata: Record<string, unknown>
  quality_gate: QualityGate
  created_by?: string
  created_at: string
  updated_at: string
}

/**
 * Create scan profile request
 */
export interface CreateScanProfileRequest {
  name: string
  description?: string
  tags?: string[]
  is_default?: boolean
  quality_gate?: QualityGate
}

/**
 * Update scan profile request
 */
export interface UpdateScanProfileRequest {
  name?: string
  description?: string
  tags?: string[]
  quality_gate?: QualityGate
}

/**
 * Update quality gate request
 */
export interface UpdateQualityGateRequest {
  enabled: boolean
  fail_on_critical: boolean
  fail_on_high: boolean
  max_critical: number
  max_high: number
  max_medium: number
  max_total: number
  new_findings_only?: boolean
  baseline_branch?: string
}

/**
 * Clone scan profile request
 */
export interface CloneScanProfileRequest {
  new_name: string
}

/**
 * Scan profile list response
 */
export interface ScanProfileListResponse {
  items: ScanProfile[]
  total: number
  page: number
  per_page: number
}

/**
 * Scan profile list filters
 */
export interface ScanProfileListFilters {
  is_default?: boolean
  is_system?: boolean
  tags?: string[]
  search?: string
  page?: number
  per_page?: number
}

// Default Quality Gate configuration
export const DEFAULT_QUALITY_GATE: QualityGate = {
  enabled: false,
  fail_on_critical: false,
  fail_on_high: false,
  max_critical: -1,
  max_high: -1,
  max_medium: -1,
  max_total: -1,
  new_findings_only: false,
  baseline_branch: '',
}

/**
 * Create a new Quality Gate with defaults
 */
export function createDefaultQualityGate(overrides?: Partial<QualityGate>): QualityGate {
  return {
    ...DEFAULT_QUALITY_GATE,
    ...overrides,
  }
}

/**
 * Check if a quality gate threshold is unlimited
 */
export function isUnlimited(value: number): boolean {
  return value < 0
}

// ============================================
// PRESET SCAN PROFILES
// ============================================

export type PresetProfileType = 'discovery' | 'quick' | 'full' | 'compliance'

export const PRESET_PROFILE_TYPES: PresetProfileType[] = [
  'discovery',
  'quick',
  'full',
  'compliance',
]

/**
 * Pass/fail rule of each preset. The name and description are i18n keys
 * (scans.profiles.preset.<type>.name / .description).
 */
export const PRESET_QUALITY_GATES: Record<PresetProfileType, QualityGate> = {
  discovery: { ...DEFAULT_QUALITY_GATE, enabled: false },
  quick: {
    ...DEFAULT_QUALITY_GATE,
    enabled: true,
    fail_on_critical: true,
    max_critical: 0,
  },
  full: {
    ...DEFAULT_QUALITY_GATE,
    enabled: true,
    fail_on_critical: true,
    fail_on_high: true,
    max_critical: 0,
    max_high: 5,
  },
  compliance: {
    ...DEFAULT_QUALITY_GATE,
    enabled: true,
    fail_on_critical: true,
    fail_on_high: true,
    max_critical: 0,
    max_high: 0,
    max_medium: 10,
  },
}

/**
 * Get a preset profile ready for API submission. The name and description
 * are already translated by the caller.
 */
export function getPresetProfileRequest(
  type: PresetProfileType,
  name: string,
  description: string
): CreateScanProfileRequest {
  return {
    name,
    description,
    quality_gate: PRESET_QUALITY_GATES[type],
    is_default: false,
  }
}
