/**
 * Pure helpers for the mapping editor. The API is the authority on every
 * rule; these only shape the editor (what to offer, how to lay it out).
 */

import type {
  CatalogAttribute,
  Direction,
  FieldMeta,
  FieldSchema,
  MappingRow,
  MappingSpec,
  TransformKind,
  ValidationIssue,
  Workflow,
  WorkflowStatus,
} from '../types/ticket-mapping.types'

/** Status categories in workflow order. */
export const CATEGORIES = ['new', 'indeterminate', 'done'] as const

export type FieldShape =
  'text' | 'number' | 'date' | 'option' | 'user' | 'labels' | 'options' | 'other'

/** Mirrors the API's shape rules (pkg/domain/ticketmap/fieldmeta.go). */
export function shapeOf(s: FieldSchema | undefined): FieldShape {
  if (!s) return 'other'
  switch (s.type) {
    case 'string':
      return 'text'
    case 'number':
      return 'number'
    case 'date':
    case 'datetime':
      return 'date'
    case 'option':
    case 'priority':
    case 'securitylevel':
    case 'resolution':
    case 'component':
    case 'version':
      return 'option'
    case 'user':
      return 'user'
    case 'array':
      if (s.items === 'string') return 'labels'
      if (s.items === 'option' || s.items === 'component' || s.items === 'version') return 'options'
  }
  return 'other'
}

/** Which directions a row may take: templates and constants only flow out;
 *  an attribute flows in only when its inbound capability allows it. */
export function allowedDirections(
  row: MappingRow,
  attr: CatalogAttribute | undefined
): Direction[] {
  if (row.source.kind !== 'attr' || !attr || attr.inbound === 'never') return ['out']
  return ['out', 'in', 'both']
}

/** A sensible transform for an attribute written to a field. */
export function defaultTransform(
  attr: CatalogAttribute | undefined,
  field: FieldMeta | undefined
): TransformKind {
  const shape = shapeOf(field?.schema)
  if (!attr) return ''
  if (shape === 'option' || shape === 'options') return 'value_map'
  if (shape === 'user') return 'user'
  if (shape === 'date') return 'date'
  if (shape === 'labels') return 'list'
  if (shape === 'text' && attr.type === 'list') return 'join'
  if (shape === 'number') return 'number'
  return ''
}

let seq = 0
/** A new, unique row id. */
export function newRowId(prefix = 'row'): string {
  seq += 1
  return `${prefix}-${Date.now().toString(36)}-${seq}`
}

/** A new row mapping an attribute to a field. */
export function rowFor(attr: CatalogAttribute, field: FieldMeta): MappingRow {
  return {
    id: newRowId(field.id.replace(/[^a-z0-9_-]/gi, '').slice(0, 30) || 'row'),
    source: { kind: 'attr', attr: attr.path },
    target: { field_id: field.id, name: field.name, schema: field.schema },
    direction: 'out',
    sync: 'always',
    transform: { kind: defaultTransform(attr, field), map: {} },
  }
}

/** Required fields of the destination that no outbound row writes. */
export function unmappedRequired(spec: MappingSpec, fields: FieldMeta[]): FieldMeta[] {
  const written = new Set(
    spec.fields.filter((r) => r.direction !== 'in').map((r) => r.target.field_id)
  )
  return fields.filter(
    (f) =>
      f.required &&
      !f.has_default &&
      !written.has(f.id) &&
      !['project', 'issuetype', 'summary'].includes(f.id)
  )
}

/** Validation issues grouped by row id ('' = the profile as a whole). */
export function issuesByRow(issues: ValidationIssue[] | undefined): Map<string, ValidationIssue[]> {
  const out = new Map<string, ValidationIssue[]>()
  for (const i of issues ?? []) {
    const k = i.row_id ?? ''
    out.set(k, [...(out.get(k) ?? []), i])
  }
  return out
}

export interface NodePos {
  status: WorkflowStatus
  x: number
  y: number
}

/** Lays the workflow out in three category columns for the graph. */
export function layoutWorkflow(wf: Workflow, colWidth = 200, rowHeight = 56): NodePos[] {
  const out: NodePos[] = []
  CATEGORIES.forEach((cat, ci) => {
    const inCat = (wf.statuses ?? []).filter((s) => s.category === cat)
    inCat.forEach((s, ri) => out.push({ status: s, x: ci * colWidth, y: ri * rowHeight }))
  })
  // Statuses with an unknown category go to the middle column, below.
  const known = new Set(out.map((n) => n.status.id))
  const extra = (wf.statuses ?? []).filter((s) => !known.has(s.id))
  const mid = out.filter((n) => n.x === colWidth).length
  extra.forEach((s, i) => out.push({ status: s, x: colWidth, y: (mid + i) * rowHeight }))
  return out
}

/** Edges of the workflow graph between laid-out nodes (global transitions are
 *  returned separately: they reach their target from anywhere). */
export function workflowEdges(wf: Workflow): {
  edges: { from: string; to: string; name: string }[]
  global: { to: string; name: string }[]
} {
  const edges: { from: string; to: string; name: string }[] = []
  const global: { to: string; name: string }[] = []
  for (const t of wf.transitions ?? []) {
    if (!t.from || t.from.length === 0) {
      global.push({ to: t.to, name: t.name })
      continue
    }
    for (const f of t.from) edges.push({ from: f, to: t.to, name: t.name })
  }
  return { edges, global }
}

/** Builds the JSON export document of a spec (same shape as the API's). */
export function exportDocument(
  spec: MappingSpec,
  objectKind: string,
  project: string,
  issueType: string
): Record<string, unknown> {
  return {
    schema: 'openctem.mapping/v1',
    object_kind: objectKind,
    project,
    issue_type: issueType,
    spec,
  }
}

/** An empty spec. */
export function emptySpec(): MappingSpec {
  return {
    minimization: 'summary',
    fields: [],
    status: { outbound: {}, inbound: [] },
    comments_out: true,
    comments_in: false,
  }
}

/** Normalizes a spec from the API (null lists become empty). */
export function normalizeSpec(spec: MappingSpec | undefined | null): MappingSpec {
  if (!spec) return emptySpec()
  return {
    ...spec,
    fields: spec.fields ?? [],
    status: {
      ...spec.status,
      outbound: spec.status?.outbound ?? {},
      inbound: spec.status?.inbound ?? [],
    },
  }
}

/** Template paths for autocomplete: `{{ path }}` snippets of the catalog. */
export function templateSnippets(attrs: CatalogAttribute[]): string[] {
  return attrs.filter((a) => a.type !== 'table').map((a) => `{{ ${a.path} }}`)
}
