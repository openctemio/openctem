/**
 * List page URLs use exactly the API's filter params (RFC-048 §3.9,
 * api/docs/rfcs/RFC-048-list-query-contract.md): `/findings?severity=critical,high&is_in_kev=true&q=log4j`
 * is both the page link and, minus page-only state, the API query. One codec
 * replaces the per-page translation layers.
 *
 * Old page links keep working: each page has a legacy alias map, applied once
 * on load (the page rewrites its URL with router.replace / replaceState).
 */

/** A legacy page param and what it becomes. `value` rewrites the value; returning null drops the param. */
export interface LegacyParamAlias {
  to: string
  value?: (v: string) => string | null
}

/** Page-only state that never goes to the API. */
export const FINDINGS_PAGE_ONLY_PARAMS = ['group', 'view', 'tab', 'density'] as const

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * The findings page's old URL vocabulary (before it used the API names).
 * `source` stays `source`, but it used to carry a data-source id the server
 * never read; a UUID value is dropped.
 */
export const FINDINGS_LEGACY_URL_ALIASES: Record<string, LegacyParamAlias> = {
  assetId: { to: 'asset_id' },
  sources: { to: 'source' },
  priority: { to: 'priority_class', value: (v) => v.toUpperCase() },
  kev: { to: 'is_in_kev', value: (v) => (v === 'true' ? 'true' : null) },
  reachable: { to: 'is_reachable', value: (v) => (v === 'true' ? 'true' : null) },
  mine: { to: 'related_to', value: (v) => (v === 'true' ? 'me' : null) },
  cve: { to: 'cve_id' },
  rule: { to: 'rule_id' },
}

/**
 * Rewrites legacy params to the current names. Returns null when nothing
 * changed. Values of a param that maps onto one already present are merged
 * (comma list).
 *
 * Findings-specific folds: `priority=kev` / `priority=reachable` were once
 * values of the priority param and become the boolean flags; `source=<uuid>`
 * (a data-source id the API never read) is dropped; a legacy table sort
 * (`sort=severity.desc`) becomes an API sort key.
 */
export function migrateLegacyParams(
  params: URLSearchParams,
  aliases: Record<string, LegacyParamAlias> = FINDINGS_LEGACY_URL_ALIASES,
  legacySort: Record<string, { api: string; invert?: boolean }> = {}
): URLSearchParams | null {
  const next = new URLSearchParams(params)
  let changed = false

  const append = (key: string, value: string) => {
    const existing = next.get(key)
    const merged = existing ? `${existing},${value}` : value
    next.set(key, Array.from(new Set(merged.split(',').filter(Boolean))).join(','))
  }

  // priority=kev / priority=reachable → the flags.
  const priority = next.get('priority')
  if (priority) {
    const parts = priority.split(',')
    if (parts.includes('kev')) next.set('is_in_kev', 'true')
    if (parts.includes('reachable')) next.set('is_reachable', 'true')
    const rest = parts.filter((p) => p !== 'kev' && p !== 'reachable' && p !== 'all')
    if (rest.length !== parts.length) {
      changed = true
      if (rest.length) next.set('priority', rest.join(','))
      else next.delete('priority')
    }
  }

  for (const [old, alias] of Object.entries(aliases)) {
    const raw = next.get(old)
    if (raw === null) continue
    next.delete(old)
    changed = true
    const values = raw
      .split(',')
      .map((v) => (alias.value ? alias.value(v) : v))
      .filter((v): v is string => !!v)
    if (values.length) append(alias.to, values.join(','))
  }

  const source = next.get('source')
  if (source) {
    const kept = source.split(',').filter((v) => !UUID_RE.test(v))
    if (kept.length !== source.split(',').length) {
      changed = true
      if (kept.length) next.set('source', kept.join(','))
      else next.delete('source')
    }
  }

  const sort = next.get('sort')
  if (sort && sort.includes('.')) {
    const [id, dir] = sort.split('.')
    const col = legacySort[id]
    changed = true
    if (col) {
      const desc = dir !== 'asc'
      const ascending = col.invert ? desc : !desc
      next.set('sort', `${ascending ? '' : '-'}${col.api}`)
    } else {
      next.delete('sort')
    }
  }

  return changed ? next : null
}

/** Joins list values with commas, skipping empty and duplicate values. */
export function joinList(values: readonly string[] | null | undefined): string | undefined {
  if (!values) return undefined
  const clean = Array.from(new Set(values.filter((v) => v !== '' && v !== 'all')))
  return clean.length ? clean.join(',') : undefined
}

/**
 * A `/findings` link in the page's (= the API's) vocabulary. Lists are
 * comma-joined; empty and false values are left out.
 */
export function findingsHref(
  filters: Record<string, string | number | boolean | readonly string[] | null | undefined>
): string {
  const q = new URLSearchParams()
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined || value === null || value === false || value === '') continue
    if (Array.isArray(value)) {
      const joined = joinList(value)
      if (joined) q.set(key, joined)
      continue
    }
    q.set(key, String(value))
  }
  const qs = q.toString()
  return qs ? `/findings?${qs}` : '/findings'
}
