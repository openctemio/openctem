/**
 * The components list keeps every filter in the URL (shareable and
 * bookmarkable). Multi-value filters are comma lists, as the API takes them.
 */

import type { ComponentFilters } from '../api/types'

/** URL filter names and their defaults ('' = no filter). */
export const COMPONENT_FILTER_DEFAULTS = {
  ecosystem: '',
  license: '',
  severity: '',
  kev: '',
  has_fix: '',
  has_vulnerabilities: '',
  relationship: '',
  scope: '',
  asset_id: '',
} as const

export type ComponentFilterName = keyof typeof COMPONENT_FILTER_DEFAULTS

export const COMPONENT_SORT_FIELDS = [
  'name',
  'assets',
  'versions',
  'risk',
  'vulns',
  'last_seen',
] as const
export const COMPONENT_DEFAULT_SORT = '-risk'
export const COMPONENT_PAGE_SIZES = [25, 50, 100] as const

/** Split a comma list into its values. */
export function listValues(raw: string | undefined): string[] {
  return (raw ?? '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)
}

/** Add or remove one value of a comma list. */
export function toggleListValue(raw: string | undefined, value: string, on: boolean): string {
  const values = listValues(raw).filter((v) => v !== value)
  if (on) values.push(value)
  return values.join(',')
}

/** Number of active filters (each selected value counts). */
export function activeFilterCount(filters: Partial<Record<ComponentFilterName, string>>): number {
  return Object.values(filters).reduce((n, v) => n + listValues(v).length, 0)
}

/** Presets: one click applies a common filter set. */
export type ComponentPreset = 'all' | 'vulnerable' | 'kev' | 'fixable' | 'direct'

export const PRESET_FILTERS: Record<
  ComponentPreset,
  Partial<Record<ComponentFilterName, string>>
> = {
  all: {},
  vulnerable: { has_vulnerabilities: 'true' },
  kev: { kev: 'true' },
  fixable: { has_fix: 'true' },
  direct: { relationship: 'direct' },
}

/** The preset the current filters equal, or null for a custom filter set. */
export function currentPreset(
  filters: Partial<Record<ComponentFilterName, string>>
): ComponentPreset | null {
  const active = Object.fromEntries(Object.entries(filters).filter(([, v]) => v)) as Record<
    string,
    string
  >
  for (const [preset, wanted] of Object.entries(PRESET_FILTERS) as [
    ComponentPreset,
    Record<string, string>,
  ][]) {
    const keys = Object.keys(wanted)
    if (keys.length !== Object.keys(active).length) continue
    if (keys.every((k) => active[k] === wanted[k])) return preset
  }
  return null
}

/** The API filters for the URL filters and search. */
export function apiFilters(
  filters: Partial<Record<ComponentFilterName, string>>,
  q: string
): ComponentFilters {
  const out: ComponentFilters = {}
  for (const [k, v] of Object.entries(filters)) {
    if (v) (out as Record<string, string>)[k] = v
  }
  if (q.trim()) out.q = q.trim()
  return out
}
