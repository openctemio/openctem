/**
 * Bug-bounty programs API types (RFC-065, /api/v1/programs).
 */

export type ProgramStatus = 'active' | 'paused' | 'ended'

export type ForbiddenTechnique =
  'dos' | 'automated_scanning' | 'intrusive' | 'social_engineering' | 'physical' | 'bruteforce'

export interface ProgramHeader {
  name: string
  value: string
}

export interface ProgramRules {
  rate_limit_rps?: number
  required_headers?: ProgramHeader[]
  user_agent?: string
  forbidden?: ForbiddenTechnique[]
  notes?: string
}

export interface ProgramActorRef {
  kind: string
  id?: string
  name?: string
}

export interface Program {
  id: string
  name: string
  platform: string
  handle: string
  program_url: string
  status: ProgramStatus
  scope_source: string
  authoritative: boolean
  rules: ProgramRules
  max_tier: string
  terms_sha256: string
  accepted_by?: ProgramActorRef
  accepted_at?: string
  group_id?: string
  created_by?: ProgramActorRef
  created_at: string
  updated_at: string
}

export interface ProgramItem {
  raw: string
  in_scope: boolean
  kind: 'domain' | 'wildcard' | 'url' | 'ip' | 'cidr' | 'other'
  target_type?: string
  pattern?: string
  asset_type?: string
  note?: string
}

export type PlannedEntryStatus = 'create' | 'keep' | 'already_covered' | 'refused'

export interface PlannedEntry {
  target_type: string
  pattern: string
  status: PlannedEntryStatus
  code?: string
  source?: string
}

export interface ProgramOverlap {
  entry_id: string
  pattern: string
  source: string
}

export interface PlannedExclusion {
  target_type: string
  pattern: string
  reason: string
  in_scope_by?: ProgramOverlap
}

export interface ProgramPreview {
  items: ProgramItem[]
  entries: PlannedEntry[]
  exclusions: PlannedExclusion[]
  not_scannable: ProgramItem[]
  max_tier: string
  terms_sha256: string
}

export interface ProgramInput {
  name: string
  platform: string
  handle: string
  program_url: string
  scope_text: string
  rules: ProgramRules
  accept_terms_sha256?: string
}

export interface ProgramEntry {
  id: string
  target_type: string
  pattern: string
  status: string
  in_effect: boolean
  max_tier: string
}

export interface ProgramDetail extends Program {
  items: ProgramItem[]
  entries: ProgramEntry[]
  exclusions: PlannedExclusion[]
}

export interface ProgramChange {
  program: Program
  preview: ProgramPreview
}
