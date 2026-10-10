/**
 * Policy selectors: which targets a policy governs. Every given dimension
 * must match (AND); any value of a dimension matches it (OR). An empty
 * selector governs every target of the organization.
 */
import { getAssetTypeLabel } from '@/features/assets/lib/asset-type-icon'
import { CRITICALITY_LABELS, type CriticalityLevel } from '@/lib/criticality'

import type { ScanWindowSelector } from '../types'
import { englishT, type Translate } from './schedule'

/** Selector dimensions that hold ids of the organization's objects. */
export const ID_DIMENSIONS = [
  'asset_group_ids',
  'business_unit_ids',
  'scan_zone_ids',
  'scope_target_ids',
  'program_ids',
] as const
export type IdDimension = (typeof ID_DIMENSIONS)[number]

/** Names of the objects a selector refers to, by dimension and id. */
export type SelectorNames = Partial<Record<IdDimension, Map<string, string>>>

/** No dimension given: the policy governs every target. */
export function isEmptySelector(s: ScanWindowSelector | undefined): boolean {
  if (!s) return true
  return (
    (s.tags?.length ?? 0) +
      (s.asset_types?.length ?? 0) +
      (s.criticalities?.length ?? 0) +
      ID_DIMENSIONS.reduce((n, d) => n + (s[d]?.length ?? 0), 0) ===
    0
  )
}

/** The selector without empty dimensions and with trimmed, unique values. */
export function cleanSelector(s: ScanWindowSelector): ScanWindowSelector {
  const out: ScanWindowSelector = {}
  const keys = ['tags', 'asset_types', 'criticalities', ...ID_DIMENSIONS] as const
  for (const k of keys) {
    const vals = [...new Set((s[k] ?? []).map((v) => v.trim()).filter(Boolean))]
    if (vals.length > 0) out[k] = vals
  }
  return out
}

const MAX_NAMED = 3

function listed(values: string[], t: Translate): string {
  const head = values.slice(0, MAX_NAMED).join(', ')
  const more = values.length - MAX_NAMED
  return more > 0 ? `${head} ${t('scanWindows.selector.more', '+{n} more', { n: more })}` : head
}

/**
 * One phrase per dimension ("Tags: prod, pci", "Zones: DMZ"); an id with no
 * known name (an object the caller cannot read) shows as "1 hidden".
 */
export function selectorParts(
  s: ScanWindowSelector | undefined,
  names: SelectorNames = {},
  t: Translate = englishT
): string[] {
  if (!s || isEmptySelector(s)) return []
  const parts: string[] = []
  const named = (dim: IdDimension, label: string) => {
    const ids = s[dim] ?? []
    if (ids.length === 0) return
    const map = names[dim]
    const known = ids.map((id) => map?.get(id)).filter((n): n is string => !!n)
    const hidden = ids.length - known.length
    const vals = [...known]
    if (hidden > 0) vals.push(t('scanWindows.selector.hidden', '{n} hidden', { n: hidden }))
    parts.push(`${label}: ${listed(vals, t)}`)
  }
  if (s.tags?.length) parts.push(`${t('scanWindows.selector.tags', 'Tags')}: ${listed(s.tags, t)}`)
  if (s.asset_types?.length)
    parts.push(
      `${t('scanWindows.selector.assetTypes', 'Asset types')}: ${listed(s.asset_types.map(getAssetTypeLabel), t)}`
    )
  if (s.criticalities?.length)
    parts.push(
      `${t('scanWindows.selector.criticality', 'Criticality')}: ${listed(
        s.criticalities.map((c) =>
          t(`criticality.${c}`, CRITICALITY_LABELS[c as CriticalityLevel] ?? c)
        ),
        t
      )}`
    )
  named('asset_group_ids', t('scanWindows.selector.groups', 'Groups'))
  named('business_unit_ids', t('scanWindows.selector.units', 'Business units'))
  named('scan_zone_ids', t('scanWindows.selector.zones', 'Zones'))
  named('scope_target_ids', t('scanWindows.selector.scope', 'Scope entries'))
  named('program_ids', t('scanWindows.selector.programs', 'Programs'))
  return parts
}

/** The selector in one line; "Every target" when empty. */
export function selectorSummary(
  s: ScanWindowSelector | undefined,
  names: SelectorNames = {},
  t: Translate = englishT
): string {
  const parts = selectorParts(s, names, t)
  return parts.length === 0 ? t('scanWindows.selector.every', 'Every target') : parts.join(' · ')
}
