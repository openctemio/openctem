/**
 * The inventory's active filters as chips (research/242 D6): one chip per
 * filter in the URL, read through the same facet registry the filter picker
 * and the phone sheet use, so every filter that narrows the list is visible
 * and removable in one click. A chip's `clear` returns the filters without
 * it (and back on page 1). Pure: the component only draws them.
 */

import type { FacetGroup, FacetT } from './inventory-facets'
import { ATTRIBUTION_FILTER_VALUES, type InventoryFilters } from './inventory-url'

export interface InventoryChip {
  /** Stable key (the filter it reads). */
  key: string
  /** What the chip says, already translated: "Criticality is Critical, High". */
  text: string
  clear: (f: InventoryFilters) => InventoryFilters
}

export interface ChipContext {
  groups: FacetGroup[]
  t: FacetT
  /** Label of a type attribute key (`os_family` → "OS family"). */
  propertyLabel: (key: string) => string
  /** A date as the viewer reads it. */
  formatDate: (iso: string) => string
}

type Tw = (key: string, fallback: string, vars?: Record<string, string | number>) => string

/** Values shown on a chip before "+N". */
const SHOWN_VALUES = 3

function list(values: string[]): string {
  return values.length > SHOWN_VALUES
    ? `${values.slice(0, SHOWN_VALUES).join(', ')} +${values.length - SHOWN_VALUES}`
    : values.join(', ')
}

function without(...keys: (keyof InventoryFilters)[]) {
  return (f: InventoryFilters): InventoryFilters => {
    const next: InventoryFilters = { ...f, page: 1 }
    for (const k of keys) delete next[k]
    return next
  }
}

export function inventoryChips(filters: InventoryFilters, ctx: ChipContext): InventoryChip[] {
  const t = ctx.t as Tw
  const is = (field: string, values: string[]) =>
    t('assets.chip.is', '{field} is {values}', { field, values: list(values) })
  const chips: InventoryChip[] = []

  for (const facet of ctx.groups.flatMap((g) => g.facets)) {
    if (facet.kind === 'multi') {
      const values = (filters[facet.filterKey] as string[] | undefined) ?? []
      if (values.length === 0) continue
      const allAttribution =
        facet.filterKey === 'attribution' &&
        (values.includes('all') || ATTRIBUTION_FILTER_VALUES.every((v) => values.includes(v)))
      chips.push({
        key: facet.filterKey,
        text: allAttribution
          ? t('assets.chip.allAttribution', 'Every name, including awaiting review and not ours')
          : is(
              facet.label,
              values.map((v) => facet.labelFor?.(v) ?? v)
            ),
        clear: without(facet.filterKey),
      })
    } else {
      const v = filters[facet.filterKey]
      if (v === undefined) continue
      chips.push({
        key: facet.filterKey,
        text: v ? facet.trueLabel : facet.falseLabel,
        clear: without(facet.filterKey),
      })
    }
  }

  if (filters.subType) {
    chips.push({
      key: 'subType',
      text: is(t('assets.chip.subType', 'Sub-type'), [filters.subType]),
      clear: without('subType'),
    })
  }
  for (const [key, values] of Object.entries(filters.propertiesFilter ?? {})) {
    if (values.length === 0) continue
    chips.push({
      key: `prop:${key}`,
      text: is(ctx.propertyLabel(key), values),
      clear: (f) => {
        const rest = { ...(f.propertiesFilter ?? {}) }
        delete rest[key]
        return { ...f, propertiesFilter: Object.keys(rest).length ? rest : undefined, page: 1 }
      },
    })
  }
  if (filters.tags?.length) {
    chips.push({
      key: 'tags',
      text:
        filters.tagsMode === 'all'
          ? t('assets.chip.tagsAll', 'Tags include all of {values}', {
              values: list(filters.tags),
            })
          : is(t('assets.chip.tags', 'Tag'), filters.tags),
      clear: without('tags', 'tagsMode'),
    })
  }
  if (filters.excludeTags?.length) {
    chips.push({
      key: 'excludeTags',
      text: t('assets.chip.isNot', '{field} is not {values}', {
        field: t('assets.chip.tags', 'Tag'),
        values: list(filters.excludeTags),
      }),
      clear: without('excludeTags'),
    })
  }
  if (filters.technologies?.length) {
    chips.push({
      key: 'technologies',
      text: is(t('assets.chip.technology', 'Technology'), filters.technologies),
      clear: without('technologies'),
    })
  }
  if (filters.technologyCategories?.length) {
    chips.push({
      key: 'technologyCategories',
      text: is(
        t('assets.chip.technologyCategory', 'Technology category'),
        filters.technologyCategories
      ),
      clear: without('technologyCategories'),
    })
  }
  if (filters.isCrownJewel !== undefined) {
    chips.push({
      key: 'isCrownJewel',
      text: filters.isCrownJewel
        ? t('assets.facetPanel.crown', 'Crown jewels')
        : t('assets.facetPanel.notCrown', 'Not a crown jewel'),
      clear: without('isCrownJewel'),
    })
  }
  if (filters.hasFindings !== undefined) {
    chips.push({
      key: 'hasFindings',
      text: filters.hasFindings
        ? t('assets.facetPanel.hasFindings', 'Has findings')
        : t('assets.facetPanel.noFindings', 'No findings'),
      clear: without('hasFindings'),
    })
  }
  if (filters.minRiskScore !== undefined) {
    chips.push({
      key: 'minRiskScore',
      text: t('assets.chip.minRisk', 'Risk score at least {value}', {
        value: filters.minRiskScore,
      }),
      clear: without('minRiskScore'),
    })
  }
  if (filters.coverage) {
    chips.push({
      key: 'coverage',
      text:
        filters.coverage === 'covered'
          ? t('assets.facetPanel.covered', 'Scanned successfully in 30 days')
          : t('assets.facetPanel.uncovered', 'No successful scan in 30 days'),
      clear: without('coverage'),
    })
  }
  if (filters.freshness) {
    chips.push({
      key: 'freshness',
      text:
        filters.freshness === 'never'
          ? t('assetFreshness.filter.never', 'Never enriched')
          : t('assetFreshness.filter.stale', 'Stale data'),
      clear: without('freshness'),
    })
  }
  if (filters.programAssets) {
    chips.push({
      key: 'programAssets',
      text:
        filters.programAssets === 'only'
          ? t('assets.views.bugBounty', 'Bug bounty')
          : t('assets.chip.programAssets', 'Program assets: {value}', {
              value: filters.programAssets,
            }),
      clear: without('programAssets'),
    })
  }
  const range = (
    key: string,
    field: string,
    after: string | undefined,
    before: string | undefined,
    keys: (keyof InventoryFilters)[]
  ) => {
    if (!after && !before) return
    const text =
      after && before
        ? t('assets.chip.between', '{field} between {from} and {to}', {
            field,
            from: ctx.formatDate(after),
            to: ctx.formatDate(before),
          })
        : after
          ? t('assets.chip.after', '{field} after {value}', { field, value: ctx.formatDate(after) })
          : t('assets.chip.before', '{field} before {value}', {
              field,
              value: ctx.formatDate(before!),
            })
    chips.push({ key, text, clear: without(...keys) })
  }
  range(
    'lastSeen',
    t('assets.chip.lastSeen', 'Last seen'),
    filters.lastSeenAfter,
    filters.lastSeenBefore,
    ['lastSeenAfter', 'lastSeenBefore']
  )
  range(
    'expires',
    t('assets.chip.expires', 'Expires'),
    filters.expiresAfter,
    filters.expiresBefore,
    ['expiresAfter', 'expiresBefore']
  )
  range('firstSeen', t('assets.chip.firstSeen', 'First seen'), filters.firstSeenAfter, undefined, [
    'firstSeenAfter',
  ])
  return chips
}
