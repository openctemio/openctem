/**
 * The findings list's filters as the API describes them
 * (`GET /meta/filters/findings`): fields, types, operators and the flat query
 * params that carry them (`severity`, `severity_not`, `epss_score_gte`...).
 * The page URL uses those same params, so a filter is a URL param and a chip is
 * a reading of one. Nothing here is specific to a field: a field added to the
 * API registry is listed, editable and shown as a chip without a web change.
 */

export type FilterOp =
  'in' | 'not_in' | 'eq' | 'ne' | 'gte' | 'gt' | 'lte' | 'lt' | 'contains' | 'is_null'

export type FieldType = 'enum' | 'string' | 'id' | 'integer' | 'number' | 'boolean' | 'date-time'

export interface FieldContract {
  name: string
  type: FieldType | string
  ops: FilterOp[]
  params?: string[]
  enum?: string[]
  sortable?: boolean
  nullable?: boolean
}

export interface FilterContract {
  resource?: string
  fields: FieldContract[]
  reserved?: string[]
  aliases?: Record<string, string>
}

/** Response of GET /meta/filters/findings. */
export interface FilterContractResponse {
  contract: FilterContract
}

/** Params that shape the list but are not filters. */
export const NON_FILTER_PARAMS: ReadonlySet<string> = new Set([
  'page',
  'per_page',
  'sort',
  'q',
  'group',
  'view',
  'density',
  'columns',
  'tab',
  'state',
  'strict',
])

/** The URL suffix each operator uses, longest first (`_gte` before `_gt`). */
const SUFFIXES: Array<{ suffix: string; ops: FilterOp[] }> = [
  { suffix: '_contains', ops: ['contains'] },
  { suffix: '_null', ops: ['is_null'] },
  { suffix: '_not', ops: ['not_in', 'ne'] },
  { suffix: '_gte', ops: ['gte'] },
  { suffix: '_lte', ops: ['lte'] },
  { suffix: '_gt', ops: ['gt'] },
  { suffix: '_lt', ops: ['lt'] },
]

/** The operator a bare `field=value` param means for this field. */
function bareOp(field: FieldContract): FilterOp | undefined {
  return (['in', 'eq', 'contains'] as const).find((op) => field.ops.includes(op))
}

/** The URL param that carries `op` on `field`, or undefined when the field cannot. */
export function paramFor(field: FieldContract, op: FilterOp): string | undefined {
  if (!field.ops.includes(op) && !(op === 'not_in' && field.ops.includes('ne'))) return undefined
  if (op === bareOp(field)) return field.name
  const suffix = SUFFIXES.find((s) => s.ops.includes(op))
  return suffix ? `${field.name}${suffix.suffix}` : undefined
}

export interface ParamMeaning {
  field: FieldContract
  op: FilterOp
}

/** What a URL param means under the contract, or undefined when it is no filter param. */
export function paramMeaning(param: string, contract: FilterContract): ParamMeaning | undefined {
  for (const field of contract.fields) {
    if (param === field.name) {
      const op = bareOp(field)
      if (op) return { field, op }
      continue
    }
    for (const { suffix, ops } of SUFFIXES) {
      if (param !== `${field.name}${suffix}`) continue
      const op = ops.find((o) => field.ops.includes(o))
      if (op) return { field, op }
    }
  }
  return undefined
}

export interface ActiveFilter {
  /** The URL param that holds it (unique in the URL). */
  param: string
  field: string
  op: FilterOp
  values: string[]
  /** Comes from the open saved view: shown, never removable here. */
  locked?: boolean
}

const LIST_OPS: ReadonlySet<FilterOp> = new Set(['in', 'not_in'])

/** Splits a param's value the way its operator reads it. */
export function valuesOf(op: FilterOp, raw: string): string[] {
  if (LIST_OPS.has(op)) {
    return raw
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean)
  }
  return raw === '' ? [] : [raw]
}

export interface ReadFilters {
  filters: ActiveFilter[]
  /** URL params that are neither a filter, nor a page param, nor owned elsewhere. */
  unknown: string[]
}

/**
 * The filters in a page URL. `skip` holds params something else draws (the
 * context chips, the search box); they are neither filters here nor unknown.
 */
export function readFilters(
  search: URLSearchParams,
  contract: FilterContract,
  skip: ReadonlySet<string> = new Set()
): ReadFilters {
  const filters: ActiveFilter[] = []
  const unknown: string[] = []
  const seen = new Set<string>()
  for (const [param, raw] of search.entries()) {
    if (NON_FILTER_PARAMS.has(param) || skip.has(param) || seen.has(param)) continue
    seen.add(param)
    const meaning = paramMeaning(param, contract)
    if (!meaning) {
      unknown.push(param)
      continue
    }
    const values = valuesOf(meaning.op, raw)
    if (values.length === 0) continue
    filters.push({ param, field: meaning.field.name, op: meaning.op, values })
  }
  return { filters, unknown }
}

interface DocLeaf {
  field: string
  op: string
  value: unknown
}

const isLeaf = (n: unknown): n is DocLeaf =>
  !!n && typeof n === 'object' && 'field' in n && 'op' in n && 'value' in n

/**
 * The filters of an open saved view, locked. A view is stored as a filter
 * document, `{"v":1,"filter":{"all":[{"field","op","value"},...]},"q":...,"sort":[...]}`
 * (the API's own form). Its top-level conditions become chips; an `any` or a
 * `not` below the top is not a chip, so the view is reported as complex and
 * the page names it with one locked chip instead of guessing.
 */
export function viewFilters(
  doc: Record<string, unknown> | undefined,
  contract: FilterContract
): { filters: ActiveFilter[]; complex: boolean } {
  const root = doc?.filter as Record<string, unknown> | undefined
  if (!root || typeof root !== 'object') return { filters: [], complex: false }
  const nodes: unknown[] | null = isLeaf(root) ? [root] : Array.isArray(root.all) ? root.all : null
  if (!nodes) return { filters: [], complex: true }
  const filters: ActiveFilter[] = []
  let complex = false
  for (const node of nodes) {
    if (!isLeaf(node)) {
      complex = true
      continue
    }
    const field = contract.fields.find((f) => f.name === node.field)
    const op = node.op as FilterOp
    const param = field ? paramFor(field, op) : undefined
    if (!field || !param) {
      complex = true
      continue
    }
    const values = (Array.isArray(node.value) ? node.value : [node.value])
      .filter((v) => v !== null && v !== undefined && typeof v !== 'object')
      .map(String)
    if (values.length === 0) continue
    filters.push({ param, field: field.name, op, values, locked: true })
  }
  return { filters, complex }
}

/** The fields an open saved view already sets: a filter on one would override the view's. */
export function viewFields(doc: Record<string, unknown> | undefined): Set<string> {
  const root = doc?.filter as Record<string, unknown> | undefined
  const nodes: unknown[] = !root
    ? []
    : isLeaf(root)
      ? [root]
      : Array.isArray(root.all)
        ? root.all
        : []
  return new Set(nodes.filter(isLeaf).map((n) => n.field))
}

/** `search` with the filter set: any value of the same param is replaced, the page resets. */
export function withFilter(
  search: URLSearchParams,
  field: FieldContract,
  op: FilterOp,
  values: string[]
): URLSearchParams {
  const param = paramFor(field, op)
  const next = new URLSearchParams(search)
  if (!param) return next
  next.delete(param)
  next.delete('page')
  const clean = values.map((v) => v.trim()).filter(Boolean)
  if (clean.length > 0) next.set(param, LIST_OPS.has(op) ? clean.join(',') : clean[0])
  return next
}

/** `search` without one param, the page reset. */
export function withoutParam(search: URLSearchParams, param: string): URLSearchParams {
  const next = new URLSearchParams(search)
  next.delete(param)
  next.delete('page')
  return next
}

/** Operators in the order a person expects them. */
const OP_ORDER: FilterOp[] = [
  'in',
  'eq',
  'not_in',
  'ne',
  'gte',
  'gt',
  'lte',
  'lt',
  'contains',
  'is_null',
]

/** The operators a person can pick on a field (`ne` and `not_in` are one: "is not"). */
export function editableOps(field: FieldContract): FilterOp[] {
  const ops = OP_ORDER.filter((o) => field.ops.includes(o))
  return ops.filter((o) => !(o === 'ne' && ops.includes('not_in')))
}

/** The entity a field belongs to in the picker, in display order. */
export const FIELD_GROUPS = ['exploitation', 'finding', 'asset', 'work', 'other'] as const
export type FieldGroup = (typeof FIELD_GROUPS)[number]

const GROUP_OF: Record<string, FieldGroup> = {
  epss_score: 'exploitation',
  is_in_kev: 'exploitation',
  kev_ransomware: 'exploitation',
  exploit_available: 'exploitation',
  is_reachable: 'exploitation',
  asset_tag: 'asset',
  asset_criticality: 'asset',
  asset_group_id: 'asset',
  asset_owner_id: 'asset',
  assigned_to: 'work',
  related_to: 'work',
  pending_approval: 'work',
}

/** Fields that are not asked for in the picker: the page owns them or they are plumbing. */
const NOT_PICKABLE: ReadonlySet<string> = new Set([
  'id',
  'state',
  'asset_id',
  'branch_id',
  'open_on_branch_id',
  'fixed_on_branch_id',
  'vulnerability_id',
  'component_id',
])

/** Fields derived from the asset: reading them needs permission to read assets. */
export const ASSET_FIELDS: ReadonlySet<string> = new Set([
  'asset_tag',
  'asset_criticality',
  'asset_group_id',
  'asset_owner_id',
])

export function groupOf(field: string): FieldGroup {
  return GROUP_OF[field] ?? (field in KNOWN_FINDING_FIELDS ? 'finding' : 'other')
}

/** Fields of the finding itself the picker groups under "Finding". */
const KNOWN_FINDING_FIELDS: Record<string, true> = Object.fromEntries(
  [
    'severity',
    'priority_class',
    'status',
    'sla_status',
    'sla_deadline',
    'source',
    'tool_name',
    'rule_id',
    'cve_id',
    'family',
    'finding_type',
    'cvss_score',
    'first_detected_at',
    'last_seen_at',
    'resolved_at',
    'created_at',
    'updated_at',
    'observation',
    'validation',
    'file_path',
    'branch_only',
    'scan_id',
    'network_port',
    'network_transport',
    'network_service',
    'acceptance_expires_at',
  ].map((k) => [k, true as const])
)

export interface PickableOptions {
  /** The viewer may read assets; without it the asset-derived fields are not offered. */
  canReadAssets: boolean
}

/** The fields the Add filter picker lists, grouped, each group in the contract's order. */
export function pickableFields(
  contract: FilterContract,
  { canReadAssets }: PickableOptions
): Array<{ group: FieldGroup; fields: FieldContract[] }> {
  const byGroup = new Map<FieldGroup, FieldContract[]>()
  for (const field of contract.fields) {
    if (NOT_PICKABLE.has(field.name)) continue
    if (ASSET_FIELDS.has(field.name) && !canReadAssets) continue
    if (editableOps(field).length === 0) continue
    const group = groupOf(field.name)
    byGroup.set(group, [...(byGroup.get(group) ?? []), field])
  }
  return FIELD_GROUPS.filter((g) => byGroup.has(g)).map((group) => ({
    group,
    fields: byGroup.get(group)!,
  }))
}

/** "first_detected_at" → "First detected at": the label of a field the web has no name for. */
export function humanize(name: string): string {
  const spaced = name.replace(/_/g, ' ').trim()
  return spaced.charAt(0).toUpperCase() + spaced.slice(1)
}

/** True when `values` are a legal value of an enum field. */
export function isEnumValue(field: FieldContract, value: string): boolean {
  return !field.enum || field.enum.includes(value)
}
