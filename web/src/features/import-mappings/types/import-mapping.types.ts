/**
 * Tenant import mappings: a declarative mapping document
 * (`openctem.io/mapping/v1`, see the ctis docs/mapping.md) that turns a CSV,
 * JSON, JSON Lines or XML export into CTIS findings and assets.
 * Wire types of /api/v1/import-mappings, hand-written in the feature.
 */

export const MAPPING_API_VERSION = 'openctem.io/mapping/v1'

export type MappingSource = 'csv' | 'json' | 'jsonl' | 'xml'
export const MAPPING_SOURCES: MappingSource[] = ['csv', 'json', 'jsonl', 'xml']

export type RuleKind = 'finding' | 'asset' | 'dependency'

/** A constant: a string, number, boolean or list of strings. */
export type ConstValue = string | number | boolean | string[]

export type CsvDelimiter = 'auto' | ',' | ';' | '\t' | '|'

export interface CsvOptions {
  delimiter?: CsvDelimiter
  skip_rows?: number
}

/** One predicate of a rule's `when`. */
export interface Predicate {
  path: string
  exists?: boolean
  equals?: string | number | boolean
  in?: (string | number | boolean)[]
  matches?: string
}

/** A value spec in object form (a bare string is a source path). */
export interface ValueSpecObject {
  path?: string
  const?: ConstValue
  template?: string
  vars?: Record<string, string>
  first?: boolean
  trim?: boolean
  lower?: boolean
  upper?: boolean
  split?: string
  map?: Record<string, string | number | boolean>
  join?: string
  as?: 'integer' | 'boolean' | 'string'
  max_bytes?: number
  default?: ConstValue
}

export type ValueSpec = string | ValueSpecObject

export interface MappingRule {
  when?: Predicate | Predicate[]
  kind: RuleKind
  set: Record<string, ValueSpec>
}

export interface MappingDocument {
  apiVersion: string
  source: MappingSource
  notes?: string
  each?: string
  csv?: CsvOptions
  identity?: string[]
  records: MappingRule[]
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

export interface ImportMapping {
  id: string
  name: string
  description: string
  source: MappingSource
  latest_version: number
  created_at: string
  updated_at: string
}

export interface MappingVersionSummary {
  version: number
  digest: string
  identity: string[]
  identity_changed: boolean
  note: string
  created_at: string
  created_by?: string
}

export interface MappingVersion extends MappingVersionSummary {
  mapping: MappingDocument
}

export interface ImportMappingDetail {
  mapping: ImportMapping
  version: MappingVersion
  versions: MappingVersionSummary[]
}

export interface MappingWithVersion {
  mapping: ImportMapping
  version: MappingVersion
}

export interface MappingTemplate {
  key: string
  name: string
  description: string
  source: MappingSource
  mapping: MappingDocument
}

export interface ValidateResult {
  valid: boolean
  errors: string[]
  source: MappingSource
  identity: string[]
}

export type PreviewWarningCode =
  'identity_collision' | 'no_records' | 'unmapped_fields' | 'truncated'

export interface PreviewItem {
  index: number
  kind: 'finding' | 'asset'
  record: Record<string, unknown>
  identity_key: string
  identity: Record<string, string>
}

export interface PreviewResult {
  items: PreviewItem[]
  stats: {
    records: number
    findings: number
    assets: number
    skipped: number
    truncated: boolean
  }
  warnings: { code: PreviewWarningCode | string; message: string }[]
  issues: { record: number; rule: number; message: string }[]
  fields: string[]
  unmapped: string[]
}
