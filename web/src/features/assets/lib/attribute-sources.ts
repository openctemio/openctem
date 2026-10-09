/**
 * Asset attribute sources (RFC-069): which source decides an asset's
 * criticality, owner, exposure and data classification, and why.
 */

export type TrackedAttribute = 'criticality' | 'owner_ref' | 'exposure' | 'data_classification'
export type SourceKind = 'manual' | 'integration' | 'import' | 'scan'
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
  criticality: ['critical', 'high', 'medium', 'low', 'none'],
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

/** The kinds an organization can list per attribute (a person's lock always wins). */
export const RANKABLE_KINDS: Exclude<SourceKind, 'manual'>[] = ['integration', 'import', 'scan']

export interface ReconciliationPolicy {
  precedence: Record<string, string[]>
  ttl_days: Record<string, number>
}

export interface ReconciliationSettings {
  precedence: Record<string, string[]>
  ttl_days: Record<string, number>
  effective: ReconciliationPolicy
  defaults: ReconciliationPolicy
}

/** The trusted kinds of an attribute in a policy, without the implied manual. */
export function trustedKinds(p: ReconciliationPolicy, attr: TrackedAttribute): string[] {
  return (p.precedence[attr] ?? []).filter((k) => k !== 'manual')
}

/** Moves item at index i by delta within a copy of list. */
export function move<T>(list: T[], i: number, delta: number): T[] {
  const j = i + delta
  if (j < 0 || j >= list.length) return list
  const out = [...list]
  ;[out[i], out[j]] = [out[j], out[i]]
  return out
}
