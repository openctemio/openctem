/**
 * The group rule as the editor works with it, and its conversions: the
 * editor's draft to the stored document, the Assets list filter to a rule,
 * and the checks that run before a preview is asked for.
 */

import type { GroupRuleDocument, GroupRuleDomain, GroupRuleFilter, GroupRuleStatus } from '../types'

/** What the rule editor holds. Text fields are raw; the document is built from them. */
export interface RuleDraft {
  /** One domain per line, `example.com` or `*.example.com`. */
  domainsText: string
  /** Whether a plain domain also takes the names below it. */
  subdomains: boolean
  types: string[]
  criticalities: string[]
  environments: string[]
  /** Tags, any of them. */
  tags: string[]
  /** Only internet-facing assets. */
  internetFacing: boolean
  search: string
  /** Scope entry ids the assets must be covered by. */
  coveredBy: string[]
  includeRelated: boolean
  /** Filter fields a draft cannot edit (kept when a stored rule is opened). */
  extra: GroupRuleFilter
}

export const EMPTY_RULE_DRAFT: RuleDraft = {
  domainsText: '',
  subdomains: true,
  types: [],
  criticalities: [],
  environments: [],
  tags: [],
  internetFacing: false,
  search: '',
  coveredBy: [],
  includeRelated: false,
  extra: {},
}

const MAX_DOMAINS = 20

/** The domains of a text, one per line or separated by commas and spaces. */
export function parseDomains(text: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of text.split(/[\s,;]+/)) {
    const d = raw.trim()
    if (!d || seen.has(d.toLowerCase())) continue
    seen.add(d.toLowerCase())
    out.push(d)
  }
  return out
}

/** Whether a domain line is a name the API takes (a DNS name, `*.` allowed). */
export function isDomainLine(value: string): boolean {
  const v = value.trim().toLowerCase().replace(/\.$/, '')
  const name = v.startsWith('*.') ? v.slice(2) : v
  if (!name || name.length > 253 || !name.includes('.')) return false
  if (/^[\d.:]+$/.test(name)) return false
  return name
    .split('.')
    .every((l) => l.length >= 1 && l.length <= 63 && /^[^\s/@:?#*%\\]+$/.test(l))
}

/** The invalid domain lines of a draft. */
export function invalidDomains(draft: RuleDraft): string[] {
  return parseDomains(draft.domainsText).filter((d) => !isDomainLine(d))
}

/** Whether the draft states no condition (a rule needs at least one). */
export function isDraftEmpty(draft: RuleDraft): boolean {
  return (
    parseDomains(draft.domainsText).length === 0 &&
    draft.types.length === 0 &&
    draft.criticalities.length === 0 &&
    draft.environments.length === 0 &&
    draft.tags.length === 0 &&
    !draft.internetFacing &&
    draft.search.trim() === '' &&
    draft.coveredBy.length === 0 &&
    Object.keys(draft.extra).length === 0
  )
}

/** The rule document of a draft. */
export function draftToDocument(draft: RuleDraft): GroupRuleDocument {
  const filter: GroupRuleFilter = { ...draft.extra }
  if (draft.types.length) filter.types = draft.types
  if (draft.criticalities.length) filter.criticalities = draft.criticalities
  if (draft.environments.length) filter.environments = draft.environments
  if (draft.tags.length) filter.tags = draft.tags
  if (draft.internetFacing) filter.internet_facing = true
  if (draft.search.trim()) filter.search = draft.search.trim()
  const doc: GroupRuleDocument = { v: 1, filter }
  const domains: GroupRuleDomain[] = parseDomains(draft.domainsText)
    .slice(0, MAX_DOMAINS)
    .map((name) => ({ name, subdomains: draft.subdomains }))
  if (domains.length) doc.domains = domains
  if (draft.coveredBy.length) doc.covered_by = draft.coveredBy
  if (draft.includeRelated) doc.include_related = true
  return doc
}

const EDITED_FILTER_KEYS = new Set([
  'types',
  'criticalities',
  'environments',
  'tags',
  'internet_facing',
  'search',
])

/** The draft of a stored rule: what the editor edits, and the rest kept as is. */
export function documentToDraft(doc: GroupRuleDocument): RuleDraft {
  const f = doc.filter ?? {}
  const extra: GroupRuleFilter = {}
  for (const [k, v] of Object.entries(f)) {
    if (!EDITED_FILTER_KEYS.has(k)) (extra as Record<string, unknown>)[k] = v
  }
  const domains = doc.domains ?? []
  return {
    domainsText: domains.map((d) => d.name).join('\n'),
    subdomains: domains.length === 0 ? true : domains.every((d) => d.subdomains),
    types: f.types ?? [],
    criticalities: f.criticalities ?? [],
    environments: f.environments ?? [],
    tags: f.tags ?? [],
    internetFacing: f.internet_facing === true,
    search: f.search ?? '',
    coveredBy: doc.covered_by ?? [],
    includeRelated: doc.include_related === true,
    extra,
  }
}

// ---------------------------------------------------------------------------
// The Assets list filter as a rule.
// ---------------------------------------------------------------------------

const LIST_FIELDS: Record<
  string,
  { key: keyof GroupRuleFilter; kind: 'list' | 'text' | 'int' | 'bool' }
> = {
  name: { key: 'name', kind: 'text' },
  types: { key: 'types', kind: 'list' },
  lenses: { key: 'lenses', kind: 'list' },
  criticalities: { key: 'criticalities', kind: 'list' },
  statuses: { key: 'statuses', kind: 'list' },
  scopes: { key: 'scopes', kind: 'list' },
  exposures: { key: 'exposures', kind: 'list' },
  tags: { key: 'tags', kind: 'list' },
  tags_mode: { key: 'tags_mode', kind: 'text' },
  exclude_tags: { key: 'exclude_tags', kind: 'list' },
  search: { key: 'search', kind: 'text' },
  min_risk_score: { key: 'min_risk_score', kind: 'int' },
  max_risk_score: { key: 'max_risk_score', kind: 'int' },
  has_findings: { key: 'has_findings', kind: 'bool' },
  is_crown_jewel: { key: 'is_crown_jewel', kind: 'bool' },
  sub_type: { key: 'sub_type', kind: 'text' },
  business_unit_ids: { key: 'business_unit_ids', kind: 'list' },
  owner_ids: { key: 'owner_ids', kind: 'list' },
  in_cidr: { key: 'in_cidr', kind: 'list' },
  has_owner: { key: 'has_owner', kind: 'bool' },
  data_classifications: { key: 'data_classifications', kind: 'list' },
  is_control_plane: { key: 'is_control_plane', kind: 'bool' },
  internet_facing: { key: 'internet_facing', kind: 'bool' },
  environments: { key: 'environments', kind: 'list' },
  providers: { key: 'providers', kind: 'list' },
  attribution: { key: 'attribution', kind: 'list' },
  scope_status: { key: 'scope_status', kind: 'list' },
  technology: { key: 'technology', kind: 'list' },
  technology_category: { key: 'technology_category', kind: 'list' },
  freshness: { key: 'freshness', kind: 'text' },
  coverage: { key: 'coverage', kind: 'text' },
}

/** Query parameters that only shape the page, never the matches. */
const PAGE_PARAMS = new Set(['page', 'per_page', 'sort', 'with_triage'])

export interface FilterToRuleResult {
  rule: GroupRuleDocument
  /** Parameters a group rule cannot hold (relative dates, discovery rules, ...). */
  unsupported: string[]
}

/**
 * The rule of an Assets list filter, given the list's query parameters (what
 * buildAssetQueryParams returns). A parameter a rule cannot hold is listed
 * in `unsupported` instead of being dropped without a word.
 */
export function filterParamsToRule(params: Record<string, string>): FilterToRuleResult {
  const filter: Record<string, unknown> = {}
  const unsupported: string[] = []
  for (const [name, value] of Object.entries(params)) {
    if (PAGE_PARAMS.has(name) || value === '') continue
    const spec = LIST_FIELDS[name]
    if (!spec) {
      unsupported.push(name)
      continue
    }
    switch (spec.kind) {
      case 'list': {
        const items = value
          .split(',')
          .map((v) => v.trim())
          .filter(Boolean)
        if (items.length) filter[spec.key] = items
        break
      }
      case 'int': {
        const n = Number(value)
        if (Number.isInteger(n)) filter[spec.key] = n
        break
      }
      case 'bool':
        if (value === 'true' || value === 'false') filter[spec.key] = value === 'true'
        break
      default:
        filter[spec.key] = value
    }
  }
  return { rule: { v: 1, filter: filter as GroupRuleFilter }, unsupported }
}

/** Whether a rule has no condition (such a rule is refused). */
export function isRuleEmpty(doc: GroupRuleDocument): boolean {
  return (
    Object.keys(doc.filter ?? {}).length === 0 &&
    (doc.domains?.length ?? 0) === 0 &&
    (doc.covered_by?.length ?? 0) === 0
  )
}

/** The tone of a rule's status badge. */
export function ruleStatusNeedsAttention(status: GroupRuleStatus): boolean {
  return status === 'paused' || status === 'over_cap'
}
