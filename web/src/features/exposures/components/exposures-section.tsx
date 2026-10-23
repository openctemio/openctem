'use client'

/**
 * The Exposures section's shared chrome: its route tabs and the hand-off from a
 * type page (a stats dashboard) to the Findings list it summarises.
 */

import Link from '@/components/link'
import { ArrowRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { SectionTabs } from '@/features/shared'
import { EXPOSURES_SECTION_TABS } from '@/config/section-tabs'
import { FINDINGS_LIST_HIDDEN_STATUSES } from '@/features/findings/lib/list-defaults'
import { useTranslation } from '@/context/i18n-provider'
import type { FindingTypeStats } from '../hooks/use-finding-type-stats'

/**
 * Overview · Vulnerabilities · Secrets · Code weaknesses · Misconfigurations.
 * Placed directly under the page's `PageHeader`, like every route-tab strip
 * (see docs/ui-style-contract.md); the page's content follows with `mt-5`.
 */
export function ExposuresTabs() {
  return (
    <SectionTabs tabs={EXPOSURES_SECTION_TABS} label="Exposures sections" className="mt-4 mb-0" />
  )
}

/**
 * The Findings list filtered to these finding sources. `/findings` reads the
 * comma-separated `source` param (useUrlFilterList('source')). `state=all`
 * drops the default Open lens, so the list shows every finding the type page
 * counted (the list still hides pentest drafts and in-review findings; see
 * `listedFindingCount`).
 */
export function findingsHrefForSources(sources: readonly string[]): string {
  return `/findings?source=${sources.map(encodeURIComponent).join(',')}&state=all`
}

/**
 * How many findings the Findings list will show for these stats. The list hides
 * pentest drafts and in-review findings by default; `/findings/stats` counts
 * them. Null when the stats could not be scoped to the type (older API), where
 * only the unsplit total is known.
 */
export function listedFindingCount(stats: FindingTypeStats): number | null {
  if (!stats.scoped) return null
  const hidden = FINDINGS_LIST_HIDDEN_STATUSES.reduce(
    (acc, status) => acc + (stats.byStatus[status] || 0),
    0
  )
  return Math.max(0, stats.total - hidden)
}

/**
 * "View N findings" — the page header action of each exposure-type page. These
 * pages are summaries; the findings themselves (filter, triage, assign) live in
 * the Findings list.
 */
export function ViewFindingsButton({
  stats,
  sources,
  isLoading,
}: {
  stats: FindingTypeStats
  sources: readonly string[]
  isLoading?: boolean
}) {
  const { t } = useTranslation()
  if (isLoading || stats.total === 0) return null
  const count = listedFindingCount(stats)
  const label =
    count === null
      ? t('exposures.type.viewFindings', 'View findings')
      : count === 1
        ? t('exposures.type.viewOne', 'View 1 finding')
        : t('exposures.type.viewMany', 'View {count} findings', { count: count.toLocaleString() })
  return (
    <Button asChild variant="outline" size="sm">
      <Link href={findingsHrefForSources(sources)}>
        {label}
        <ArrowRight className="ms-2 h-4 w-4 rtl:rotate-180" />
      </Link>
    </Button>
  )
}
