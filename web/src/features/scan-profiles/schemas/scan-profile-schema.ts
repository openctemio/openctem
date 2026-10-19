import { z } from 'zod'

// Quality Gate schema for CI/CD pass/fail decisions
export const qualityGateSchema = z.object({
  enabled: z.boolean(),
  fail_on_critical: z.boolean(),
  fail_on_high: z.boolean(),
  max_critical: z.number().min(-1), // -1 = unlimited
  max_high: z.number().min(-1),
  max_medium: z.number().min(-1),
  max_total: z.number().min(-1),
  new_findings_only: z.boolean().optional(),
  baseline_branch: z.string().optional(),
})

// Quality Gate form data type
export interface QualityGateFormData {
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

// Create scan profile form data type (for form)
export interface CreateScanProfileFormData {
  name: string
  description?: string
  is_default: boolean
  quality_gate?: QualityGateFormData
}

// Create scan profile schema
export const createScanProfileSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name must be less than 100 characters'),
  description: z.string().max(500, 'Description must be less than 500 characters').optional(),
  is_default: z.boolean(),
  quality_gate: qualityGateSchema.optional(),
})

// Update scan profile form data type (for form)
export interface UpdateScanProfileFormData {
  name?: string
  description?: string
  quality_gate?: QualityGateFormData
}

// Update scan profile schema
export const updateScanProfileSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  description: z.string().max(500).optional(),
  quality_gate: qualityGateSchema.optional(),
})

// Clone scan profile form data type (for form)
export interface CloneScanProfileFormData {
  new_name: string
}

// Clone scan profile schema
export const cloneScanProfileSchema = z.object({
  new_name: z.string().min(1, 'Name is required').max(100, 'Name must be less than 100 characters'),
})

// Default Quality Gate configuration
export const DEFAULT_QUALITY_GATE: QualityGateFormData = {
  enabled: false,
  fail_on_critical: false,
  fail_on_high: false,
  max_critical: -1, // unlimited
  max_high: -1,
  max_medium: -1,
  max_total: -1,
  new_findings_only: false,
  baseline_branch: '',
}

// Quality Gate threshold presets for common use cases
export const QUALITY_GATE_PRESETS = {
  disabled: {
    label: 'Disabled',
    description: 'No quality gate enforcement',
    config: DEFAULT_QUALITY_GATE,
  },
  strict: {
    label: 'Strict',
    description: 'Fail on any critical or high severity findings',
    config: {
      enabled: true,
      fail_on_critical: true,
      fail_on_high: true,
      max_critical: 0,
      max_high: 0,
      max_medium: -1,
      max_total: -1,
      new_findings_only: false,
      baseline_branch: '',
    } satisfies QualityGateFormData,
  },
  moderate: {
    label: 'Moderate',
    description: 'Fail only on critical findings, allow up to 5 high severity',
    config: {
      enabled: true,
      fail_on_critical: true,
      fail_on_high: false,
      max_critical: 0,
      max_high: 5,
      max_medium: -1,
      max_total: -1,
      new_findings_only: false,
      baseline_branch: '',
    } satisfies QualityGateFormData,
  },
  lenient: {
    label: 'Lenient',
    description: 'Allow up to 3 critical and 10 high severity findings',
    config: {
      enabled: true,
      fail_on_critical: false,
      fail_on_high: false,
      max_critical: 3,
      max_high: 10,
      max_medium: -1,
      max_total: -1,
      new_findings_only: false,
      baseline_branch: '',
    } satisfies QualityGateFormData,
  },
} as const
