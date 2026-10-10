/**
 * Bug-bounty programs API types (RFC-065, /api/v1/programs).
 */

export type ProgramStatus = 'active' | 'paused' | 'ended' | 'pending_attestation'

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

export type ProgramScopeSource =
  'paste' | 'file_import' | 'program_api' | 'program_file' | 'public_feed'

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
  /** Feed programs: published, published_by_platform or inferred. */
  confidence?: 'published' | 'published_by_platform' | 'inferred'
  /** Port limit of the entry an in-scope target becomes ("8443", "80,443"). */
  ports?: string
  protocol?: 'tcp' | 'udp'
  /** What the program says about the target; shown, never used to authorize. */
  eligible_for_bounty?: boolean
  max_severity?: 'none' | 'low' | 'medium' | 'high' | 'critical'
  environment?: 'production' | 'staging' | 'other'
  instructions?: string
  requires?: string
}

export type PlannedEntryStatus = 'create' | 'keep' | 'already_covered' | 'refused'

export interface PlannedEntry {
  target_type: string
  pattern: string
  constraint?: { ports?: string; protocol?: string }
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
  ports?: string
  protocol?: string
}

export interface ProgramDetail extends Program {
  items: ProgramItem[]
  entries: ProgramEntry[]
  exclusions: PlannedExclusion[]
}

/** A program of the public catalog (RFC-065 §16). */
/** Where a feed record comes from (dataset fields for public datasets). */
export interface FeedProvenance {
  source: string
  source_url: string
  fetched_at: string
  dataset?: string
  dataset_commit?: string
  original_platform?: string
  original_url?: string
}

export interface PublicProgram {
  id: string
  feed_id: string
  source: string
  platform: string
  handle: string
  name: string
  url: string
  type: 'bounty' | 'vdp'
  status: 'open' | 'paused' | 'closed'
  offers_bounty: boolean
  scope_published: boolean
  in_scope: number
  suggested: number
  out_of_scope: number
  items: ProgramItem[]
  rules: ProgramRules
  terms_text: string
  terms_url?: string
  terms_doc_sha256?: string
  as_of: string
  provenance: FeedProvenance
}

export interface PublicProgramPage {
  data: PublicProgram[]
  total: number
  page: number
  per_page: number
}

export interface ProgramChange {
  program: Program
  preview: ProgramPreview
}

/** A notification integration attached to a program (RFC-065 §15.4). */
export interface ProgramChannel {
  integration_id: string
  name: string
  provider: string
  created_by?: ProgramActorRef
}

/** Where events about the program private assets go. */
export interface ProgramDelivery {
  program_id: string
  /** An owner let them reach every organization-wide integration. */
  org_channels: boolean
  channels: ProgramChannel[]
}

/** A notification integration of the organization that can be attached. */
export interface NotificationChannelOption {
  id: string
  name: string
  provider: string
}
