'use client'

/**
 * Headline numbers for the All-Assets inventory, as the shared MetricStrip.
 *
 * Each metric is also a quick filter: clicking it applies (or clears) the
 * matching filter, and its active state is read straight from the current
 * filters. Counts come from the tenant-wide /assets/stats aggregate.
 *
 * Only "Unowned" is coloured: an asset nobody owns is a gap to close. A
 * critical or internet-facing asset is important, not a problem in itself.
 *
 * "Stale" is intentionally omitted: the stats endpoint exposes no stale count,
 * and faking one from the current page would misrepresent the tenant total. The
 * "Stale >30d" view still covers that filter.
 *
 * Typed mode (research/77): the counts are the type's (or the lens's), the
 * first metric is named after it ("Hosts") and keeps it when clicked, and each of the
 * type's yes/no attributes adds a metric ("Virtual machine", "MFA") counting
 * the assets where it is true, a click filtering to them.
 */

import { MetricStrip, type MetricStripItem } from '@/features/shared'
import type { AssetStatsData } from '../../hooks/use-assets'
import {
  HIGH_RISK_SCORE,
  isInventoryFilterEmpty,
  togglePropertyFilter,
  type InventoryFilters,
} from '../../lib/inventory-url'

interface StatDef {
  id: string
  label: string
  value: number
  tone?: MetricStripItem['tone']
  active: boolean
  /** Toggle the filter this metric represents, returning the next filter state. */
  toggle: (f: InventoryFilters) => InventoryFilters
}

interface StatStripProps {
  stats: AssetStatsData
  filters: InventoryFilters
  isLoading?: boolean
  onChange: (next: InventoryFilters) => void
  className?: string
  /** Typed or lens mode: the type's plural ("Hosts") or the lens's label. */
  typeLabel?: string
  /** Typed mode: the type's yes/no attributes to count. */
  boolFacets?: { key: string; label: string }[]
}

export function InventoryStatStrip({
  stats,
  filters,
  isLoading,
  onChange,
  className,
  typeLabel,
  boolFacets = [],
}: StatStripProps) {
  const typed = typeLabel !== undefined
  const defs: StatDef[] = [
    {
      id: 'total',
      label: typeLabel ?? 'All assets',
      value: stats.total,
      active: isInventoryFilterEmpty(
        typed ? { ...filters, types: undefined, subType: undefined, lens: undefined } : filters
      ),
      // Clears every filter (keeps sort + page size, and the type or lens when typed).
      toggle: (f) =>
        typed
          ? { types: f.types, subType: f.subType, lens: f.lens, sort: f.sort, pageSize: f.pageSize }
          : { sort: f.sort, pageSize: f.pageSize },
    },
    {
      id: 'critical',
      label: 'Critical',
      value: stats.byCriticality['critical'] ?? 0,
      active: filters.criticalities?.includes('critical') ?? false,
      toggle: (f) =>
        f.criticalities?.includes('critical')
          ? { ...f, criticalities: undefined, page: 1 }
          : { ...f, criticalities: ['critical'], page: 1 },
    },
    {
      id: 'internet',
      label: 'Internet-facing',
      // One definition across the product (research/22 P0-12): exposure =
      // public, the population the Attack surface pages count.
      value: stats.byExposure['public'] ?? 0,
      active: isPublicOnly(filters.exposures),
      toggle: (f) =>
        isPublicOnly(f.exposures)
          ? { ...f, exposures: undefined, page: 1 }
          : { ...f, exposures: ['public'], page: 1 },
    },
    {
      id: 'unowned',
      label: 'Unowned',
      value: stats.byHasOwner['false'] ?? 0,
      tone: 'danger',
      active: filters.hasOwner === false,
      toggle: (f) =>
        f.hasOwner === false
          ? { ...f, hasOwner: undefined, page: 1 }
          : { ...f, hasOwner: false, page: 1 },
    },
    {
      id: 'high-risk',
      label: 'High risk',
      value: stats.highRiskCount,
      active: filters.minRiskScore === HIGH_RISK_SCORE,
      toggle: (f) =>
        f.minRiskScore === HIGH_RISK_SCORE
          ? { ...f, minRiskScore: undefined, page: 1 }
          : { ...f, minRiskScore: HIGH_RISK_SCORE, page: 1 },
    },
    {
      id: 'with-findings',
      label: 'With findings',
      value: stats.withFindings,
      active: filters.hasFindings === true,
      toggle: (f) =>
        f.hasFindings === true
          ? { ...f, hasFindings: undefined, page: 1 }
          : { ...f, hasFindings: true, page: 1 },
    },
    ...boolFacets.map((b): StatDef => ({
      id: `attr:${b.key}`,
      label: b.label,
      value: stats.metadataCounts?.[b.key]?.['true'] ?? 0,
      active: filters.propertiesFilter?.[b.key]?.includes('true') ?? false,
      toggle: (f) => togglePropertyFilter(f, b.key, 'true'),
    })),
  ]

  return (
    <MetricStrip
      className={className}
      loading={isLoading}
      items={defs.map((d) => ({
        key: d.id,
        label: d.label,
        value: d.value,
        tone: d.tone,
        active: d.active,
        onClick: () => onChange(d.toggle(filters)),
      }))}
    />
  )
}

function isPublicOnly(exposures: readonly string[] | undefined): boolean {
  return exposures?.length === 1 && exposures[0] === 'public'
}
