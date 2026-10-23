/**
 * The editor's model of a mapping document and its conversion both ways.
 *
 * The table edits one row per target of each rule; everything the table does
 * not show (a rule's `when`, notes, transforms the row editor has no control
 * for) is carried through unchanged, so document -> draft -> document keeps
 * the document (up to the bare-string form of a path-only value).
 */

import {
  MAPPING_API_VERSION,
  type ConstValue,
  type CsvOptions,
  type MappingDocument,
  type MappingRule,
  type MappingSource,
  type Predicate,
  type RuleKind,
  type ValueSpec,
  type ValueSpecObject,
} from '../types/import-mapping.types'
import { MAX_IDENTITY, REQUIRED_TARGETS, isIdentityEligible } from './targets'

export type SourceKind = 'path' | 'const' | 'template'

export interface MappingRow {
  /** Local key for React; never sent. */
  key: string
  /** CTIS target; empty while the person has not picked one. */
  target: string
  spec: ValueSpecObject
}

export interface DraftRule {
  key: string
  kind: RuleKind
  when?: Predicate | Predicate[]
  rows: MappingRow[]
  /** Members the editor does not know, kept so the API can report them. */
  extra?: Record<string, unknown>
}

export interface MappingDraft {
  apiVersion: string
  source: MappingSource
  notes?: string
  each?: string
  csv?: CsvOptions
  identity: string[]
  rules: DraftRule[]
  /** Members the editor does not know, kept so the API can report them. */
  extra?: Record<string, unknown>
}

const DOC_MEMBERS = new Set(['apiVersion', 'source', 'notes', 'each', 'csv', 'identity', 'records'])
const RULE_MEMBERS = new Set(['when', 'kind', 'set'])

function extraOf(obj: object, known: Set<string>): Record<string, unknown> | undefined {
  const extra: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(obj)) if (!known.has(k)) extra[k] = v
  return Object.keys(extra).length ? extra : undefined
}

let seq = 0
function nextKey(prefix: string): string {
  seq += 1
  return `${prefix}${seq}`
}

/** The object form of a value spec (a bare string is a source path). */
export function normalizeSpec(spec: ValueSpec): ValueSpecObject {
  return typeof spec === 'string' ? { path: spec } : { ...spec }
}

/** The shortest form: a value that is only a path is written as the bare path. */
export function compactSpec(spec: ValueSpecObject): ValueSpec {
  const keys = Object.keys(spec).filter((k) => spec[k as keyof ValueSpecObject] !== undefined)
  if (keys.length === 1 && keys[0] === 'path' && typeof spec.path === 'string') return spec.path
  const out: ValueSpecObject = {}
  for (const k of keys) {
    ;(out as Record<string, unknown>)[k] = spec[k as keyof ValueSpecObject]
  }
  return out
}

export function sourceKindOf(spec: ValueSpecObject): SourceKind {
  if (spec.template !== undefined) return 'template'
  if (spec.const !== undefined) return 'const'
  return 'path'
}

/** Switch a row's source kind, keeping its transforms. */
export function withSourceKind(spec: ValueSpecObject, kind: SourceKind): ValueSpecObject {
  if (sourceKindOf(spec) === kind) return spec
  const { path: _p, const: _c, template: _t, vars: _v, ...rest } = spec
  if (kind === 'path') return { path: '', ...rest }
  if (kind === 'const') return { const: '', ...rest }
  return { template: '', vars: {}, ...rest }
}

export function rowsFromSet(set: Record<string, ValueSpec>): MappingRow[] {
  return Object.entries(set).map(([target, spec]) => ({
    key: nextKey('row'),
    target,
    spec: normalizeSpec(spec),
  }))
}

/** Rows without a target are left out: they are still being filled in. */
export function setFromRows(rows: MappingRow[]): Record<string, ValueSpec> {
  const set: Record<string, ValueSpec> = {}
  for (const row of rows) {
    if (!row.target) continue
    set[row.target] = compactSpec(row.spec)
  }
  return set
}

export function draftFromDocument(doc: MappingDocument): MappingDraft {
  return {
    apiVersion: doc.apiVersion ?? MAPPING_API_VERSION,
    source: doc.source,
    notes: doc.notes,
    each: doc.each,
    csv: doc.csv ? { ...doc.csv } : undefined,
    identity: [...(doc.identity ?? [])],
    rules: (doc.records ?? []).map((r) => ({
      key: nextKey('rule'),
      kind: r.kind,
      when: r.when,
      rows: rowsFromSet(r.set ?? {}),
      extra: extraOf(r, RULE_MEMBERS),
    })),
    extra: extraOf(doc, DOC_MEMBERS),
  }
}

export function documentFromDraft(draft: MappingDraft): MappingDocument {
  const doc: MappingDocument = {
    ...(draft.extra ?? {}),
    apiVersion: draft.apiVersion,
    source: draft.source,
    records: [],
  }
  if (draft.notes !== undefined) doc.notes = draft.notes
  if (draft.each !== undefined && draft.each !== '') doc.each = draft.each
  if (draft.csv !== undefined) doc.csv = { ...draft.csv }
  if (draft.identity.length > 0) doc.identity = [...draft.identity]
  doc.records = draft.rules.map((r) => {
    const rule: MappingRule = { ...(r.extra ?? {}), kind: r.kind, set: setFromRows(r.rows) }
    if (r.when !== undefined) rule.when = r.when
    return rule
  })
  return doc
}

/** The canonical form a round trip produces, for comparisons and tests. */
export function normalizeDocument(doc: MappingDocument): MappingDocument {
  return documentFromDraft(draftFromDocument(doc))
}

/** Change the source type, dropping members the new type does not allow. */
export function withSource(draft: MappingDraft, source: MappingSource): MappingDraft {
  const next: MappingDraft = { ...draft, source }
  if (source !== 'csv') delete next.csv
  else next.csv = draft.csv ?? { delimiter: 'auto' }
  if (source === 'csv' || source === 'jsonl') delete next.each
  return next
}

/** Toggle a target in the identity list. */
export function toggleIdentity(draft: MappingDraft, target: string, on: boolean): MappingDraft {
  const has = draft.identity.includes(target)
  if (on === has) return draft
  return {
    ...draft,
    identity: on ? [...draft.identity, target] : draft.identity.filter((t) => t !== target),
  }
}

/** Rename a row's target; an identity member follows its row. */
export function renameTarget(
  draft: MappingDraft,
  ruleKey: string,
  rowKey: string,
  target: string
): MappingDraft {
  let previous = ''
  const rules = draft.rules.map((r) =>
    r.key !== ruleKey
      ? r
      : {
          ...r,
          rows: r.rows.map((row) => {
            if (row.key !== rowKey) return row
            previous = row.target
            return { ...row, target }
          }),
        }
  )
  let identity = draft.identity
  if (previous && identity.includes(previous)) {
    const stillSet = rules.some(
      (r) => r.kind === 'finding' && r.rows.some((row) => row.target === previous)
    )
    if (!stillSet) {
      identity = identity
        .map((t) => (t === previous ? target : t))
        .filter((t, i, all) => t && isIdentityEligible(t) && all.indexOf(t) === i)
    }
  }
  return { ...draft, rules, identity }
}

export function newRow(target = ''): MappingRow {
  return { key: nextKey('row'), target, spec: { path: '' } }
}

export function newRule(kind: RuleKind): DraftRule {
  const rows = REQUIRED_TARGETS[kind].map((t) => newRow(t))
  return { key: nextKey('rule'), kind, rows }
}

/** A blank CSV mapping: one finding per row from title and severity columns. */
export function blankDocument(): MappingDocument {
  return {
    apiVersion: MAPPING_API_VERSION,
    source: 'csv',
    csv: { delimiter: 'auto', skip_rows: 0 },
    identity: ['title'],
    records: [{ kind: 'finding', set: { title: '/title', severity: '/severity' } }],
  }
}

/** Parse a constant typed by a person: text stays text unless the original was not text. */
export function parseConstInput(text: string, previous: ConstValue | undefined): ConstValue {
  if (previous === undefined || typeof previous === 'string') return text
  try {
    const v: unknown = JSON.parse(text)
    if (
      typeof v === 'string' ||
      typeof v === 'number' ||
      typeof v === 'boolean' ||
      (Array.isArray(v) && v.every((x) => typeof x === 'string'))
    ) {
      return v as ConstValue
    }
  } catch {
    // not JSON: keep it as text
  }
  return text
}

export function formatConst(v: ConstValue | undefined): string {
  if (v === undefined) return ''
  return typeof v === 'string' ? v : JSON.stringify(v)
}

/** The transforms a row applies, in the language's order, for its summary chips. */
export function activeTransforms(spec: ValueSpecObject): string[] {
  const out: string[] = []
  if (spec.first) out.push('first')
  if (spec.trim) out.push('trim')
  if (spec.lower) out.push('lower')
  if (spec.upper) out.push('upper')
  if (spec.split !== undefined) out.push('split')
  if (spec.map !== undefined) out.push('map')
  if (spec.join !== undefined) out.push('join')
  if (spec.as !== undefined) out.push('as')
  if (spec.max_bytes !== undefined) out.push('max_bytes')
  if (spec.default !== undefined) out.push('default')
  return out
}

/** Variable names used in a template: `{host}:{port}` -> host, port. */
export function templateVars(template: string): string[] {
  const names: string[] = []
  for (const m of template.matchAll(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g)) {
    if (!names.includes(m[1])) names.push(m[1])
  }
  return names
}

export type DraftProblem =
  | { code: 'no_rules' }
  | { code: 'missing_target'; rule: number }
  | { code: 'required'; rule: number; target: string }
  | { code: 'duplicate'; rule: number; target: string }
  | { code: 'identity_required' }
  | { code: 'identity_too_many' }
  | { code: 'identity_unset'; rule: number; target: string }
  | { code: 'each_required' }

/**
 * Quick local checks so the editor can point at a row; the API's validation
 * is the authority and catches everything else.
 */
export function draftProblems(draft: MappingDraft): DraftProblem[] {
  const problems: DraftProblem[] = []
  if (draft.rules.length === 0) problems.push({ code: 'no_rules' })
  if (draft.source === 'xml' && !draft.each) problems.push({ code: 'each_required' })
  const hasFinding = draft.rules.some((r) => r.kind === 'finding')
  if (hasFinding && draft.identity.length === 0) problems.push({ code: 'identity_required' })
  if (draft.identity.length > MAX_IDENTITY) problems.push({ code: 'identity_too_many' })
  draft.rules.forEach((rule, i) => {
    const n = i + 1
    const targets = rule.rows.map((r) => r.target)
    if (targets.some((t) => !t)) problems.push({ code: 'missing_target', rule: n })
    for (const req of REQUIRED_TARGETS[rule.kind]) {
      if (!targets.includes(req)) problems.push({ code: 'required', rule: n, target: req })
    }
    const seen = new Set<string>()
    for (const t of targets) {
      if (!t) continue
      if (seen.has(t)) problems.push({ code: 'duplicate', rule: n, target: t })
      seen.add(t)
    }
    if (rule.kind === 'finding') {
      for (const id of draft.identity) {
        if (!targets.includes(id)) problems.push({ code: 'identity_unset', rule: n, target: id })
      }
    }
  })
  return problems
}
