/**
 * Asset attribute sources (RFC-069): which source decides an asset's
 * criticality, owner, exposure and data classification, and why.
 */

import { ASSET_CRITICALITY_LEVELS } from '@/lib/criticality'

export type TrackedAttribute = 'criticality' | 'owner_ref' | 'exposure' | 'data_classification'
export type SourceKind = 'manual' | 'integration' | 'import' | 'scan' | 'feed'
export type SourceStatus = 'winner' | 'outranked' | 'stale' | 'untrusted'

export interface AttributeSource {
  kind: SourceKind
  name: string
  value: string
  observed_at: string
  ingested_at: string
  confidence: number
  status: SourceStatus
}

export interface AttributeSources {
  attribute: TrackedAttribute
  value: string
  locked: boolean
  conflict: boolean
  decided_by: AttributeSource | null
  sources: AttributeSource[]
}

export interface AttributeSourcesList {
  attributes: AttributeSources[]
}

export const TRACKED_ATTRIBUTES: TrackedAttribute[] = [
  'criticality',
  'owner_ref',
  'exposure',
  'data_classification',
]

export const ATTRIBUTE_LABEL: Record<TrackedAttribute, string> = {
  criticality: 'Criticality',
  owner_ref: 'Owner reference',
  exposure: 'Exposure',
  data_classification: 'Data classification',
}

export const SOURCE_KIND_LABEL: Record<SourceKind, string> = {
  manual: 'A person',
  integration: 'Integration',
  import: 'Import',
  scan: 'Scan',
  feed: 'Feed',
}

export const SOURCE_STATUS_LABEL: Record<SourceStatus, string> = {
  winner: 'Decides',
  outranked: 'Outranked',
  stale: 'Stale',
  untrusted: 'Not trusted',
}

export const SOURCE_STATUS_HINT: Record<SourceStatus, string> = {
  winner: 'The value the asset shows.',
  outranked: 'Counts, but a more trusted or more recent source wins.',
  stale: 'Not reported within its time limit, so it no longer counts.',
  untrusted: 'Your organization does not trust this kind of source for this attribute.',
}

/** The values an attribute accepts; null = free text. */
export const ATTRIBUTE_VALUES: Record<TrackedAttribute, string[] | null> = {
  criticality: [...ASSET_CRITICALITY_LEVELS],
  exposure: ['public', 'restricted', 'private', 'isolated', 'unknown'],
  data_classification: ['', 'public', 'internal', 'confidential', 'restricted', 'secret'],
  owner_ref: null,
}

/** How a value reads; an empty one is "Not set". */
export function displayValue(v: string): string {
  return v.trim() === '' ? 'Not set' : v
}

/** One line saying who decides the attribute. */
export function decidedByText(a: AttributeSources): string {
  if (a.locked) return 'Set by a person, locked until released'
  const w = a.decided_by
  if (!w) {
    return a.sources.length === 0
      ? 'No source has reported it'
      : 'No trusted, current source: the value is kept'
  }
  const who = w.name ? `${SOURCE_KIND_LABEL[w.kind]} (${w.name})` : SOURCE_KIND_LABEL[w.kind]
  return `${who}`
}

/** "2 sources disagree" when the counted sources report different values. */
export function conflictText(a: AttributeSources): string | null {
  if (!a.conflict) return null
  const counted = a.sources.filter((s) => s.status === 'winner' || s.status === 'outranked')
  const distinct = new Set(counted.map((s) => s.value)).size
  return `${distinct} sources disagree`
}

// ---------------------------------------------------------------------------
// Source precedence settings (RFC-069 §12): a ranked list of source rules per
// attribute class, and a default list the classes inherit.

/** The kinds an organization ranks (a person's lock always wins). */
export type RankableKind = Exclude<SourceKind, 'manual'>
export const RANKABLE_KINDS: RankableKind[] = ['integration', 'scan', 'import', 'feed']

export type AttributeClass =
  'identity' | 'network' | 'software' | 'ownership' | 'cloud_tags' | 'lifecycle'

export const ATTRIBUTE_CLASSES: AttributeClass[] = [
  'identity',
  'network',
  'software',
  'ownership',
  'cloud_tags',
  'lifecycle',
]

/** One row: a kind ("scan") or one source of a kind ("scan:nmap"). */
export interface SourceRule {
  source: string
  ttl_days: number
  trusted: boolean
}

export interface SourcePolicy {
  default: SourceRule[]
  classes: Partial<Record<AttributeClass, SourceRule[]>>
}

export interface SourceSummary {
  kind: RankableKind
  name: string
  last_seen: string
  assets: number
}

export interface ReconciliationSettings {
  saved: SourcePolicy
  effective: SourcePolicy
  defaults: SourcePolicy
  classes: { class: AttributeClass; attributes: TrackedAttribute[] }[]
  sources: SourceSummary[]
}

export interface PreviewChange {
  asset_id: string
  asset_name: string
  attribute: TrackedAttribute
  current: string
  next: string
  next_source: string
  conflict: boolean
}

export interface PolicyPreview {
  scanned_assets: number
  truncated: boolean
  changed_assets: number
  changed_values: number
  conflicts: number
  samples: PreviewChange[]
}

export const MAX_TTL_DAYS = 3650

/** The kind and source name of a rule ("" for the whole kind). */
export function ruleParts(source: string): { kind: RankableKind; name: string } {
  const i = source.indexOf(':')
  if (i < 0) return { kind: source as RankableKind, name: '' }
  return { kind: source.slice(0, i) as RankableKind, name: source.slice(i + 1) }
}

/** When the rule's source (or any source of its kind) last reported. */
export function lastSeenFor(source: string, sources: SourceSummary[]): string | null {
  const { kind, name } = ruleParts(source)
  let best: string | null = null
  for (const s of sources) {
    if (s.kind !== kind || (name && s.name !== name)) continue
    if (!best || s.last_seen > best) best = s.last_seen
  }
  return best
}

/** Moves the item at index from to index to in a copy of list. */
export function moveItem<T>(list: T[], from: number, to: number): T[] {
  if (from === to || from < 0 || to < 0 || from >= list.length || to >= list.length) return list
  const out = [...list]
  const [item] = out.splice(from, 1)
  out.splice(to, 0, item)
  return out
}

/** A copy of a policy safe to edit. */
export function clonePolicy(p: SourcePolicy): SourcePolicy {
  const classes: SourcePolicy['classes'] = {}
  for (const c of ATTRIBUTE_CLASSES) {
    const list = p.classes?.[c]
    if (list) classes[c] = list.map((r) => ({ ...r }))
  }
  return { default: (p.default ?? []).map((r) => ({ ...r })), classes }
}

/** Whether a rule's TTL is a whole number of days in range. */
export function ttlValid(ttl: number): boolean {
  return Number.isInteger(ttl) && ttl >= 0 && ttl <= MAX_TTL_DAYS
}

/** Whether every rule of the policy is valid. */
export function policyValid(p: SourcePolicy): boolean {
  const lists = [p.default, ...Object.values(p.classes).filter(Boolean)] as SourceRule[][]
  return lists.every((l) => l.every((r) => ttlValid(r.ttl_days)))
}
