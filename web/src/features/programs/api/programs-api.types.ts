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

export type WeekDay = 'sun' | 'mon' | 'tue' | 'wed' | 'thu' | 'fri' | 'sat'

/** When a program allows testing: days, HH:MM start to end, IANA zone. */
export interface TestingWindow {
  days: WeekDay[]
  start: string
  end: string
  timezone: string
}

export interface ProgramRules {
  rate_limit_rps?: number
  required_headers?: ProgramHeader[]
  user_agent?: string
  forbidden?: ForbiddenTechnique[]
  notes?: string
  testing_windows?: TestingWindow[]
}

export type ProgramScopeSource = 'paste' | 'file_import' | 'program_api' | 'program_file'

/** Who sees a program (RFC-065 §15): private = members and owners only. */
export type ProgramVisibility = 'private' | 'public'

export type ScopeFileFormat = 'auto' | 'platform_csv' | 'burp_json' | 'generic_csv' | 'text'

/** Columns of a generic CSV: identifier required, type and in-scope optional. */
export interface ScopeFileMapping {
  identifier: string
  type?: string
  in_scope?: string
}

/** A scope file read in the browser and sent as text (at most 256 KiB). */
export interface ScopeFileInput {
  format: ScopeFileFormat
  name: string
  content: string
  mapping?: ScopeFileMapping
}

/** Where a program's scope comes from; the API token is never returned. */
export interface ProgramSync {
  url?: string
  handle?: string
  username?: string
  has_token: boolean
  last_synced_at?: string
  last_error?: string
}

export interface ProgramSourceInput {
  scope_source: ProgramScopeSource
  url?: string
  handle?: string
  username?: string
  /** Empty keeps the stored token. */
  token?: string
}

export interface ProgramSyncResult {
  program: Program
  removed_entries: number
  added_exclusions: number
  pending_additions: number
  suspended: boolean
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
  visibility: ProgramVisibility
  terms_text: string
  /** Private and the caller has not accepted its current terms: details hidden. */
  locked: boolean
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
  sync?: ProgramSync
  /** A sync found new scope: nothing is added until someone accepts these terms. */
  pending_terms_sha256?: string
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
  /** Replaces scope_text when set. */
  scope_file?: ScopeFileInput
  terms_text: string
  /** Read on import only. */
  visibility?: ProgramVisibility
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
