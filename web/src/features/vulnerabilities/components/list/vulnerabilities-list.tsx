'use client'

/**
 * The vulnerabilities list `/vulnerabilities` (api/docs/architecture/vulnerability-page.md,
 * "The list"): one row per CVE across the assets the caller may see, sorted by
 * risk. Every filter lives in the URL (the API's own params), every count on a
 * row opens the findings list that counts it, and a row opens the
 * vulnerability page. Producer and feed text renders as text.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef, SortingState } from '@tanstack/react-table'
import { Bug, Clock, Flame, RefreshCw, ShieldCheck } from 'lucide-react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { KevBadge } from '@/components/ui/kev-badge'
import { PriorityBadge } from '@/components/ui/priority-badge'
import { SignalChip } from '@/components/ui/signal-chip'
import { useTranslation } from '@/context/i18n-provider'
import { useAssetGroupsApi } from '@/features/asset-groups/api/use-asset-groups-api'
import { DataTable } from '@/features/shared/components/data-table'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import {
  FacetOption,
  FacetPanel,
  FacetSection,
  FacetToggle,
} from '@/features/shared/components/facet-filter-panel'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { FilterSelect } from '@/features/shared/components/filter-select'
import { MetricStrip, type MetricStripItem } from '@/features/shared/components/metric-strip'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { PageHeader } from '@/features/shared/components/page-header'
import { PageStack } from '@/features/shared/components/page-stack'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import { dateFnsLocaleFor } from '@/features/shared/components/activity-timeline'
import { useSearchQuery } from '@/hooks/use-search-query'
import { replaceUrlSearch, useUrlParams, useUrlSettled } from '@/hooks/use-url-param'
import { useSeverityLabel } from '@/hooks/use-scale-labels'
import { formatEpssScore } from '@/lib/epss'
import { EpssSparkline } from '../epss-trend'
import { SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import type { SeverityLevel } from '@/lib/severity'
import { toDisplayText } from '@/lib/untrusted-text'
import { safeHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'
import { useCanReadVulnList, useVulnerabilityList } from '../../api/use-vulnerability-list'
import { vulnerabilityHref } from '../../api/use-cve-exposure'
import { CveLink } from '../cve-link'
import { FilterLayout, useFilterPanelOpen } from '../vulnerability-filters'
import {
  activeFilterCount,
  buildVulnListQuery,
  headlineFixVersion,
  kevDueDays,
  readEpss,
  readFlag,
  readList,
  readPage,
  readSearch,
  readSort,
  readState,
  remediationState,
  rowFindingsHref,
  sortToSorting,
  sortingToSort,
  VULN_LIST_EPSS,
  VULN_LIST_PAGE_SIZES,
  VULN_LIST_PRIORITIES,
  VULN_LIST_SEVERITIES,
  VULN_LIST_SORTS,
  VULN_LIST_SOURCES,
  VULN_LIST_STATES,
  type VulnListFlag,
  type VulnListState,
} from '../../lib/vuln-list'
import type { VulnListItem } from '../../types/list'

const PANEL_ID = 'vulnerability-list-filters'

type Patch = Record<string, string | null>

/** Writes params to the URL in one step; any change but paging goes back to page 1. */
function patchUrl(changes: Patch, keepPage = false) {
  const next = new URLSearchParams(window.location.search)
  for (const [k, v] of Object.entries(changes)) {
    if (v === null || v === '') next.delete(k)
    else next.set(k, v)
  }
  if (!keepPage) next.delete('page')
  replaceUrlSearch(next)
}

function toggleIn(list: string[], v: string): string[] {
  return list.includes(v) ? list.filter((x) => x !== v) : [...list, v]
}

export function VulnerabilitiesList() {
  const { t } = useTranslation()
  const canRead = useCanReadVulnList()

  if (!canRead) {
    return (
      <Main>
        <NoAccessState title={t('vulnPage.list.subject', 'the vulnerabilities list')} />
      </Main>
    )
  }
  return <VulnerabilitiesListBody />
}

function VulnerabilitiesListBody() {
  const { t, locale } = useTranslation()
  const router = useRouter()
  const severityLabel = useSeverityLabel()
  const dateLocale = dateFnsLocaleFor(locale)
  const urlSettled = useUrlSettled()
  const params = useUrlParams()
  const query = useMemo(() => buildVulnListQuery(params), [params])
  const { data, error, isLoading, isValidating, mutate } = useVulnerabilityList(query, urlSettled)
  const panel = useFilterPanelOpen('vuln-list-filters-open')
  const [groupsWanted, setGroupsWanted] = useState(false)
  const groups = useAssetGroupsApi(groupsWanted ? { per_page: 100, sort_by: 'name' } : null)
  const groupOptions = useMemo(
    () =>
      (groups.data?.data ?? []).flatMap((g) => (g.id ? [{ id: g.id, name: g.name ?? '' }] : [])),
    [groups.data]
  )

  const state = readState(params)
  const sort = readSort(params)
  const { page, perPage } = readPage(params)
  const severities = readList(params, 'severity')
  const priorities = readList(params, 'priority_class')
  const sources = readList(params, 'source')
  const groupIds = readList(params, 'asset_group_id')
  const epss = readEpss(params)
  const flag = (f: VulnListFlag) => readFlag(params, f)
  const filterCount = activeFilterCount(params)

  // Typed search reaches the URL (and so the request) only once settled.
  const [searchInput, setSearchInput] = useState(() => readSearch(params))
  const { term } = useSearchQuery(searchInput)
  useEffect(() => {
    if (term !== readSearch(new URLSearchParams(window.location.search))) patchUrl({ q: term })
  }, [term])

  const setFlag = useCallback(
    (f: VulnListFlag, on: boolean) => patchUrl({ [f]: on ? 'true' : null }),
    []
  )
  const setList = useCallback(
    (key: string, values: string[]) => patchUrl({ [key]: values.length ? values.join(',') : null }),
    []
  )
  const clearAll = useCallback(() => {
    patchUrl({
      severity: null,
      priority_class: null,
      source: null,
      asset_group_id: null,
      kev: null,
      exploit: null,
      emerging: null,
      past_sla: null,
      has_fix: null,
      epss_gte: null,
    })
  }, [])

  const rows = useMemo(() => data?.data ?? [], [data])
  const total = data?.total ?? 0
  const summary = data?.summary

  // Every tile is a filter (research/244): All clears the exploitation
  // filters, the others toggle their own.
  const strip: MetricStripItem[] = [
    {
      key: 'all',
      label: t('vulnPage.list.strip.all', 'Vulnerabilities'),
      value: summary?.total ?? 0,
      description: t(
        'vulnPage.list.strip.allHint',
        'Distinct vulnerabilities on the assets you can see, under the current filters'
      ),
      active: !flag('kev') && !flag('exploit') && !flag('emerging') && !flag('past_sla'),
      onClick: () => patchUrl({ kev: null, exploit: null, emerging: null, past_sla: null }),
    },
    {
      key: 'kev',
      label: t('vulnPage.list.strip.kev', 'Known exploited'),
      value: summary?.kev ?? 0,
      tone: 'danger',
      description: t('vulnPage.list.strip.kevHint', 'Listed in the known exploited catalog (KEV)'),
      active: flag('kev') === true,
      onClick: () => setFlag('kev', flag('kev') !== true),
    },
    {
      key: 'exploit',
      label: t('vulnPage.list.strip.exploit', 'Public exploit'),
      value: summary?.exploit ?? 0,
      tone: 'warning',
      description: t(
        'vulnPage.list.strip.exploitHint',
        'A public exploit or proof of concept is known'
      ),
      active: flag('exploit') === true,
      onClick: () => setFlag('exploit', flag('exploit') !== true),
    },
    {
      key: 'emerging',
      label: t('vulnPage.list.strip.emerging', 'Emerging threats'),
      value: summary?.emerging ?? 0,
      tone: 'danger',
      description: t(
        'vulnPage.list.strip.emergingHint',
        'An open emerging-threat alert names one of your assets'
      ),
      active: flag('emerging') === true,
      onClick: () => setFlag('emerging', flag('emerging') !== true),
    },
    {
      key: 'past_sla',
      label: t('vulnPage.list.strip.pastSla', 'Past SLA'),
      value: summary?.past_sla ?? 0,
      tone: 'danger',
      description: t(
        'vulnPage.list.strip.pastSlaHint',
        'At least one open finding is past its SLA'
      ),
      active: flag('past_sla') === true,
      onClick: () => setFlag('past_sla', flag('past_sla') !== true),
    },
  ]

  const sourceLabel = useCallback(
    (s: string) => t(`vulnPage.list.source.${s}`, s.toUpperCase()),
    [t]
  )
  const groupName = useCallback(
    (id: string) => groups.data?.data?.find((g) => g.id === id)?.name,
    [groups.data]
  )

  // The active filters as chips, each removable on its own.
  const chips: { key: string; text: string; clear: Patch }[] = []
  const flagText: Record<VulnListFlag, [string, string]> = {
    kev: [
      t('vulnPage.list.chip.kev', 'Known exploited'),
      t('vulnPage.list.chip.notKev', 'Not known exploited'),
    ],
    exploit: [
      t('vulnPage.list.chip.exploit', 'Public exploit'),
      t('vulnPage.list.chip.noExploit', 'No public exploit'),
    ],
    emerging: [
      t('vulnPage.list.chip.emerging', 'Emerging threat'),
      t('vulnPage.list.chip.notEmerging', 'No emerging threat'),
    ],
    past_sla: [
      t('vulnPage.list.chip.pastSla', 'Past SLA'),
      t('vulnPage.list.chip.pastSla', 'Past SLA'),
    ],
    has_fix: [
      t('vulnPage.list.chip.hasFix', 'Fix available'),
      t('vulnPage.list.chip.noFix', 'No fix yet'),
    ],
  }
  for (const f of ['kev', 'exploit', 'emerging', 'past_sla', 'has_fix'] as VulnListFlag[]) {
    const v = flag(f)
    if (v !== undefined) chips.push({ key: f, text: flagText[f][v ? 0 : 1], clear: { [f]: null } })
  }
  if (epss) {
    chips.push({
      key: 'epss',
      text: t('vulnPage.list.chip.epss', 'EPSS at least {value}', {
        value: formatEpssScore(Number(epss), 0),
      }),
      clear: { epss_gte: null },
    })
  }
  const listChip = (key: string, label: string, values: string[], show: (v: string) => string) => {
    if (!values.length) return
    const shown = values.slice(0, 3).map(show).join(', ')
    chips.push({
      key,
      text: `${label}: ${values.length > 3 ? `${shown} +${values.length - 3}` : shown}`,
      clear: { [key]: null },
    })
  }
  listChip('severity', t('vulnPage.list.facet.severity', 'Severity'), severities, (v) =>
    severityLabel(v as SeverityLevel)
  )
  listChip('priority_class', t('vulnPage.list.facet.priority', 'Priority'), priorities, (v) => v)
  listChip('source', t('vulnPage.list.facet.source', 'Source'), sources, sourceLabel)
  listChip('asset_group_id', t('vulnPage.list.facet.assetGroup', 'Asset group'), groupIds, (id) =>
    toDisplayText(groupName(id) ?? t('vulnPage.list.chip.oneGroup', 'a group'), 60)
  )

  const resultLabel = data
    ? t(
        'vulnPage.list.results',
        '{count, plural, one {# vulnerability} other {# vulnerabilities}}',
        {
          count: total,
        }
      )
    : undefined

  const chipsRow =
    chips.length > 0 ? (
      <FilterChipsRow
        label={t('vulnPage.list.activeFilters', 'Active filters')}
        chips={chips.map((c) => (
          <RemovableFilterChip
            key={c.key}
            text={c.text}
            onRemove={() => patchUrl(c.clear)}
            removeLabel={t('vulnPage.list.removeFilter', 'Remove filter {filter}', {
              filter: c.text,
            })}
          />
        ))}
        trailing={
          chips.length > 1 ? (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-xs text-muted-foreground"
              onClick={clearAll}
            >
              {t('vulnPage.list.clearFilters', 'Clear filters')}
            </Button>
          ) : undefined
        }
        end={resultLabel ? <span role="status">{resultLabel}</span> : undefined}
      />
    ) : undefined

  const facetPanel = (
    <FacetPanel activeCount={filterCount} onClearAll={clearAll}>
      <FacetToggle
        label={t('vulnPage.list.facet.kev', 'Known exploited')}
        description={t('vulnPage.list.facet.kevHint', 'Exploited in the wild (KEV catalog)')}
        checked={flag('kev') === true}
        onCheckedChange={(v) => setFlag('kev', v)}
      />
      <FacetToggle
        label={t('vulnPage.list.facet.exploit', 'Public exploit')}
        description={t(
          'vulnPage.list.facet.exploitHint',
          'An exploit or proof of concept is public'
        )}
        checked={flag('exploit') === true}
        onCheckedChange={(v) => setFlag('exploit', v)}
      />
      <FacetToggle
        label={t('vulnPage.list.facet.emerging', 'Emerging threat')}
        description={t(
          'vulnPage.list.facet.emergingHint',
          'An open alert names one of your assets'
        )}
        checked={flag('emerging') === true}
        onCheckedChange={(v) => setFlag('emerging', v)}
      />
      <FacetToggle
        label={t('vulnPage.list.facet.pastSla', 'Past SLA')}
        description={t('vulnPage.list.facet.pastSlaHint', 'At least one open finding is overdue')}
        checked={flag('past_sla') === true}
        onCheckedChange={(v) => setFlag('past_sla', v)}
      />
      <FacetSection
        title={t('vulnPage.list.facet.epss', 'Exploit probability (EPSS)')}
        selectedCount={epss ? 1 : 0}
      >
        {VULN_LIST_EPSS.map((v) => (
          <FacetOption
            key={v}
            label={t('vulnPage.list.facet.epssAtLeast', '{value} or higher', {
              value: formatEpssScore(Number(v), 0),
            })}
            checked={epss === v}
            onCheckedChange={(on) => patchUrl({ epss_gte: on ? v : null })}
          />
        ))}
      </FacetSection>
      <FacetSection
        title={t('vulnPage.list.facet.fix', 'Fix')}
        selectedCount={flag('has_fix') !== undefined ? 1 : 0}
      >
        <FacetOption
          label={t('vulnPage.list.facet.hasFix', 'A fixed version is known')}
          checked={flag('has_fix') === true}
          onCheckedChange={(on) => patchUrl({ has_fix: on ? 'true' : null })}
        />
        <FacetOption
          label={t('vulnPage.list.facet.noFix', 'No fix yet')}
          checked={flag('has_fix') === false}
          onCheckedChange={(on) => patchUrl({ has_fix: on ? 'false' : null })}
        />
      </FacetSection>
      <FacetSection
        title={t('vulnPage.list.facet.severity', 'Severity')}
        selectedCount={severities.length}
      >
        {VULN_LIST_SEVERITIES.map((v) => (
          <FacetOption
            key={v}
            label={severityLabel(v)}
            checked={severities.includes(v)}
            onCheckedChange={() => setList('severity', toggleIn(severities, v))}
            adornment={
              <span className={cn('size-2 shrink-0 rounded-full', SEVERITY_DOT_COLORS[v])} />
            }
          />
        ))}
      </FacetSection>
      <FacetSection
        title={t('vulnPage.list.facet.priority', 'Priority')}
        selectedCount={priorities.length}
        defaultOpen={false}
      >
        {VULN_LIST_PRIORITIES.map((v) => (
          <FacetOption
            key={v}
            label={<PriorityBadge priorityClass={v} showWord />}
            checked={priorities.includes(v)}
            onCheckedChange={() => setList('priority_class', toggleIn(priorities, v))}
          />
        ))}
      </FacetSection>
      <FacetSection
        title={t('vulnPage.list.facet.source', 'Source')}
        selectedCount={sources.length}
        defaultOpen={false}
      >
        {VULN_LIST_SOURCES.map((v) => (
          <FacetOption
            key={v}
            label={sourceLabel(v)}
            checked={sources.includes(v)}
            onCheckedChange={() => setList('source', toggleIn(sources, v))}
          />
        ))}
      </FacetSection>
      <FacetSection
        title={t('vulnPage.list.facet.assetGroup', 'Asset group')}
        selectedCount={groupIds.length}
        defaultOpen={false}
        onOpenChange={(open) => open && setGroupsWanted(true)}
      >
        {groups.isLoading ? (
          <p className="py-1 text-xs text-muted-foreground">
            {t('vulnPage.list.facet.loading', 'Loading…')}
          </p>
        ) : groupOptions.length === 0 ? (
          <p className="py-1 text-xs text-muted-foreground">
            {t('vulnPage.list.facet.noGroups', 'No asset groups yet.')}
          </p>
        ) : (
          groupOptions.map((g) => (
            <FacetOption
              key={g.id}
              label={toDisplayText(g.name, 60)}
              checked={groupIds.includes(g.id)}
              onCheckedChange={() => setList('asset_group_id', toggleIn(groupIds, g.id))}
            />
          ))
        )}
      </FacetSection>
    </FacetPanel>
  )

  const columns = useMemo<ColumnDef<VulnListItem>[]>(
    () => [
      {
        id: 'cve',
        header: t('vulnPage.list.col.vulnerability', 'Vulnerability'),
        enableSorting: true,
        enableHiding: false,
        cell: ({ row }) => <VulnCell item={row.original} />,
      },
      {
        id: 'signals',
        header: t('vulnPage.list.col.signals', 'Exploitation'),
        enableSorting: false,
        cell: ({ row }) => <SignalsCell item={row.original} />,
      },
      {
        id: 'priority',
        header: t('vulnPage.list.col.priority', 'Priority'),
        enableSorting: false,
        cell: ({ row }) => <PriorityBadge priorityClass={row.original.worst_priority || null} />,
      },
      {
        id: 'cvss',
        header: t('vulnPage.list.col.severity', 'Severity'),
        enableSorting: true,
        cell: ({ row }) => (
          <span className="flex items-center gap-2 whitespace-nowrap">
            <SeverityBadge severity={row.original.severity} />
            {row.original.cvss_score != null && (
              <span className="text-muted-foreground tabular-nums">
                {row.original.cvss_score.toFixed(1)}
              </span>
            )}
          </span>
        ),
      },
      {
        id: 'epss',
        header: t('vulnPage.list.col.epss', 'EPSS'),
        enableSorting: true,
        cell: ({ row }) => (
          <span className="flex flex-col gap-0.5">
            <span
              className="tabular-nums"
              title={
                row.original.epss_percentile != null
                  ? t('vulnPage.list.epssPercentile', 'Higher than {pct} of all CVEs', {
                      pct: formatEpssScore(row.original.epss_percentile, 0),
                    })
                  : undefined
              }
            >
              {formatEpssScore(row.original.epss_score, 1, '—')}
            </span>
            <EpssSparkline points={row.original.epss_trend} />
          </span>
        ),
      },
      {
        id: 'assets',
        header: t('vulnPage.list.col.assets', 'Assets'),
        enableSorting: true,
        cell: ({ row }) => <AssetsCell item={row.original} params={params} />,
      },
      {
        id: 'product',
        header: t('vulnPage.list.col.product', 'Affected product'),
        enableSorting: false,
        cell: ({ row }) => <ProductCell item={row.original} />,
      },
      {
        id: 'fix',
        header: t('vulnPage.list.col.fix', 'Fix'),
        enableSorting: false,
        cell: ({ row }) => <FixCell item={row.original} />,
      },
      {
        id: 'remediation',
        header: t('vulnPage.list.col.remediation', 'Remediation'),
        enableSorting: false,
        cell: ({ row }) => <RemediationCell item={row.original} params={params} />,
      },
      {
        id: 'findings',
        header: t('vulnPage.list.col.findings', 'Findings'),
        enableSorting: true,
        cell: ({ row }) => (
          <Link
            href={safeHref(rowFindingsHref(row.original.cve_id, params)) ?? '/findings'}
            onClick={(e) => e.stopPropagation()}
            className="tabular-nums hover:underline"
          >
            {row.original.findings.toLocaleString()}
          </Link>
        ),
      },
      {
        id: 'kev_due',
        header: t('vulnPage.list.col.kevDue', 'KEV due'),
        enableSorting: true,
        cell: ({ row }) => <KevDueText due={row.original.kev_due_date} />,
      },
      {
        id: 'first_seen',
        header: t('vulnPage.list.col.firstSeen', 'First seen'),
        enableSorting: true,
        cell: ({ row }) => (
          <RelativeTime
            date={row.original.first_seen_at}
            locale={dateLocale}
            className="whitespace-nowrap"
          />
        ),
      },
      {
        id: 'last_seen',
        header: t('vulnPage.list.col.lastSeen', 'Last seen'),
        enableSorting: true,
        cell: ({ row }) => (
          <RelativeTime
            date={row.original.last_seen_at}
            locale={dateLocale}
            className="whitespace-nowrap"
          />
        ),
      },
    ],
    [t, params, dateLocale]
  )

  const sorting = useMemo(() => sortToSorting(sort), [sort])
  const onSortingChange = useCallback(
    (next: SortingState) => patchUrl({ sort: sortingToSort(next) || null }),
    []
  )
  const pagination = useMemo(() => ({ pageIndex: page - 1, pageSize: perPage }), [page, perPage])
  const onPaginationChange = useCallback(
    (next: { pageIndex: number; pageSize: number }) => {
      const sizeChanged = next.pageSize !== perPage
      patchUrl(
        {
          page: sizeChanged || next.pageIndex === 0 ? null : String(next.pageIndex + 1),
          per_page: next.pageSize === 25 ? null : String(next.pageSize),
        },
        true
      )
    },
    [perPage]
  )

  const stateLabel = (s: VulnListState) =>
    ({
      open: t('vulnPage.list.state.open', 'Open'),
      fixed: t('vulnPage.list.state.fixed', 'Fixed'),
      dispositioned: t('vulnPage.list.state.dispositioned', 'Accepted or false positive'),
      all: t('vulnPage.list.state.all', 'All'),
    })[s]
  const sortLabel: Record<string, string> = {
    risk: t('vulnPage.list.sort.risk', 'Risk'),
    epss: t('vulnPage.list.sort.epss', 'EPSS'),
    cvss: t('vulnPage.list.sort.cvss', 'Severity (CVSS)'),
    assets: t('vulnPage.list.sort.assets', 'Most assets'),
    findings: t('vulnPage.list.sort.findings', 'Most findings'),
    kev_due: t('vulnPage.list.sort.kevDue', 'KEV due date'),
    last_seen: t('vulnPage.list.sort.lastSeen', 'Last seen'),
    first_seen: t('vulnPage.list.sort.firstSeen', 'Newest'),
    cve: t('vulnPage.list.sort.cve', 'CVE id'),
  }

  const toolbarStart = (
    <>
      <FilterSelect<VulnListState>
        label={t('vulnPage.list.state.label', 'Findings')}
        value={state}
        clearable={false}
        options={VULN_LIST_STATES.map((s) => ({ value: s, label: stateLabel(s) }))}
        onChange={(v) => patchUrl({ state: v && v !== 'open' ? v : null })}
      />
      <FilterSelect<string>
        label={t('vulnPage.list.sort.label', 'Sort')}
        value={sort.key}
        clearable={false}
        options={VULN_LIST_SORTS.map((s) => ({ value: s, label: sortLabel[s] }))}
        onChange={(v) => patchUrl({ sort: v && v !== 'risk' ? v : null })}
      />
    </>
  )

  const toolbarEnd = (
    <Button
      variant="outline"
      size="icon"
      className="h-9 w-9"
      onClick={() => void mutate()}
      disabled={isValidating}
      aria-label={t('vulnPage.list.refresh', 'Refresh')}
      title={t('vulnPage.list.refresh', 'Refresh')}
    >
      <RefreshCw
        className={cn('h-4 w-4', isValidating && 'animate-spin motion-reduce:animate-none')}
        aria-hidden
      />
    </Button>
  )

  const searching = readSearch(params) !== ''
  const emptyState =
    filterCount > 0 || searching || state !== 'open' ? (
      <EmptyState
        icon={ShieldCheck}
        title={t('vulnPage.list.empty.filteredTitle', 'No vulnerability matches these filters')}
        description={t(
          'vulnPage.list.empty.filteredHint',
          'Remove a filter, clear the search or switch the findings to All.'
        )}
        action={
          filterCount > 0 ? (
            <Button variant="outline" size="sm" onClick={clearAll}>
              {t('vulnPage.list.clearFilters', 'Clear filters')}
            </Button>
          ) : undefined
        }
      />
    ) : (
      <EmptyState
        icon={Bug}
        title={t('vulnPage.list.empty.title', 'No open vulnerabilities on the assets you can see')}
        description={t(
          'vulnPage.list.empty.hint',
          'Vulnerabilities appear here once a scan, an import or the software inventory reports a CVE on one of your assets.'
        )}
        action={
          <Button asChild variant="outline" size="sm">
            <Link href="/exposures/vulnerabilities?tab=catalog">
              {t('vulnPage.list.empty.catalog', 'Browse the CVE catalog')}
            </Link>
          </Button>
        }
      />
    )

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('vulnPage.list.title', 'Vulnerabilities')}
          description={t(
            'vulnPage.list.description',
            'One row per vulnerability across the assets you can see, sorted by risk: priority, known exploitation, emerging threats, EPSS, CVSS and reach.'
          )}
        />
        <MetricStrip items={strip} loading={!data && !error} />
        <FilterLayout
          panelId={PANEL_ID}
          label={t('vulnPage.list.filtersTitle', 'Vulnerability filters')}
          open={panel.open}
          sheetOpen={panel.sheetOpen}
          onSheetOpenChange={panel.setSheetOpen}
          panel={facetPanel}
        >
          {error ? (
            <ErrorState
              title={t('vulnPage.list.subject', 'the vulnerabilities list')}
              error={error}
              onRetry={() => void mutate()}
            />
          ) : (
            <DataTable
              columns={columns}
              data={rows}
              showSearch={false}
              search={{
                value: searchInput,
                onChange: setSearchInput,
                placeholder: t(
                  'vulnPage.list.searchPlaceholder',
                  'Search CVE, advisory id or title…'
                ),
                label: t('vulnPage.list.searchLabel', 'Search vulnerabilities'),
              }}
              filterToggle={{
                open: panel.open,
                onToggle: panel.toggle,
                onOpenSheet: () => panel.setSheetOpen(true),
                activeCount: filterCount,
                controlsId: PANEL_ID,
              }}
              toolbarStart={toolbarStart}
              toolbarEnd={toolbarEnd}
              toolbarBelow={chipsRow}
              getRowId={(r) => r.cve_id}
              manualPagination
              rowCount={total}
              pageCount={Math.max(1, data?.total_pages ?? 1)}
              pagination={pagination}
              onPaginationChange={onPaginationChange}
              pageSizeOptions={VULN_LIST_PAGE_SIZES}
              sorting={sorting}
              onSortingChange={onSortingChange}
              isLoading={isLoading}
              onRowClick={(r) => router.push(vulnerabilityHref(r.cve_id))}
              initialColumnVisibility={{
                product: false,
                findings: false,
                kev_due: false,
                first_seen: false,
              }}
              mobileRow={(r) => (
                <MobileVulnRow item={r} onOpen={() => router.push(vulnerabilityHref(r.cve_id))} />
              )}
              paginationNoun={t('vulnPage.list.noun', 'vulnerabilities')}
              emptyState={emptyState}
            />
          )}
        </FilterLayout>
        <p className="text-xs text-muted-foreground">
          {t(
            'vulnPage.list.scopeNote',
            'Counts are in your data scope. Assets outside it are not shown or counted.'
          )}
        </p>
      </PageStack>
    </Main>
  )
}

/** The CVE (link), the title and the first aliases. */
function VulnCell({ item }: { item: VulnListItem }) {
  const { t } = useTranslation()
  const title = item.title && item.title !== item.cve_id ? toDisplayText(item.title, 200) : ''
  return (
    <div className="min-w-[13rem] max-w-[18rem]">
      <CveLink id={item.cve_id} stopPropagation className="font-medium" />
      {title ? (
        <p className="truncate text-muted-foreground" title={title}>
          {title}
        </p>
      ) : !item.in_catalog ? (
        <p className="text-muted-foreground">
          {t('vulnPage.list.notInCatalog', 'Not in the feed yet')}
        </p>
      ) : null}
      {item.aliases.length > 0 && (
        <p
          className="truncate font-mono text-xs text-muted-foreground"
          title={item.aliases.join(', ')}
        >
          {item.aliases.slice(0, 2).join(', ')}
          {item.aliases.length > 2 ? ` +${item.aliases.length - 2}` : ''}
        </p>
      )}
    </div>
  )
}

/** KEV (with due state), emerging threat, public exploit, past SLA: text chips. */
function SignalsCell({ item }: { item: VulnListItem }) {
  const { t } = useTranslation()
  const days = kevDueDays(item.kev_due_date)
  const chips = []
  if (item.kev) {
    chips.push(
      <KevBadge
        key="kev"
        className="whitespace-nowrap"
        ransomware={item.kev_ransomware}
        pastDue={days !== undefined && days < 0}
      />
    )
  }
  if (item.emerging) {
    chips.push(
      <SignalChip key="em" icon={Flame} tone="alert" className="whitespace-nowrap">
        <Link
          href={`/emerging-threats/${encodeURIComponent(item.emerging.id)}`}
          onClick={(e) => e.stopPropagation()}
          className="hover:underline"
        >
          {t('vulnPage.list.signal.emerging', 'Emerging threat')}
        </Link>
      </SignalChip>
    )
  }
  if (item.exploit) {
    const maturity = item.exploit_maturity
    chips.push(
      <SignalChip key="ex" icon={Bug} className="whitespace-nowrap">
        {maturity === 'weaponized'
          ? t('vulnPage.list.signal.weaponized', 'Weaponized')
          : maturity === 'functional'
            ? t('vulnPage.list.signal.functional', 'Working exploit')
            : maturity === 'poc'
              ? t('vulnPage.list.signal.poc', 'Proof of concept')
              : t('vulnPage.list.signal.exploit', 'Public exploit')}
      </SignalChip>
    )
  }
  if (item.past_sla > 0) {
    chips.push(
      <SignalChip key="sla" icon={Clock} tone="alert" alertText className="whitespace-nowrap">
        {t('vulnPage.list.signal.pastSla', '{count} past SLA', { count: item.past_sla })}
      </SignalChip>
    )
  }
  if (chips.length === 0) {
    return (
      <span className="text-muted-foreground">{t('vulnPage.list.signal.none', 'No signal')}</span>
    )
  }
  return <div className="flex max-w-[16rem] flex-wrap items-center gap-1">{chips}</div>
}

function KevDueText({ due }: { due?: string }) {
  const { t } = useTranslation()
  const days = kevDueDays(due)
  if (days === undefined) return <span className="text-muted-foreground">—</span>
  return (
    <span className={cn('whitespace-nowrap', days < 0 && 'text-destructive')}>
      {days < 0
        ? t('vulnPage.list.kevPastDue', '{days, plural, one {# day} other {# days}} past due', {
            days: -days,
          })
        : t('vulnPage.list.kevDueIn', 'Due in {days, plural, one {# day} other {# days}}', {
            days,
          })}
    </span>
  )
}

function AssetsCell({ item, params }: { item: VulnListItem; params: URLSearchParams }) {
  const { t } = useTranslation()
  return (
    <div className="whitespace-nowrap">
      <Link
        href={safeHref(rowFindingsHref(item.cve_id, params, { group: 'asset_id' })) ?? '/findings'}
        onClick={(e) => e.stopPropagation()}
        className="font-medium tabular-nums hover:underline"
        aria-label={t('vulnPage.list.assetsAria', '{count} assets: open the findings by asset', {
          count: item.assets,
        })}
      >
        {item.assets.toLocaleString()}
      </Link>
      {item.internet_facing_assets > 0 && (
        <p className="text-xs text-muted-foreground">
          {t('vulnPage.list.internet', '{count} internet-facing', {
            count: item.internet_facing_assets,
          })}
        </p>
      )}
    </div>
  )
}

function ProductCell({ item }: { item: VulnListItem }) {
  const { t } = useTranslation()
  const p = item.products[0]
  if (!p) return <span className="text-muted-foreground">—</span>
  const versions = p.versions.slice(0, 2).join(', ')
  const name = toDisplayText(p.name, 80)
  return (
    <div className="max-w-[14rem]">
      <p className="truncate" title={name}>
        {name}
      </p>
      {versions && (
        <p
          className="truncate font-mono text-xs text-muted-foreground"
          title={p.versions.join(', ')}
        >
          {toDisplayText(versions, 80)}
          {p.versions.length > 2 ? ` +${p.versions.length - 2}` : ''}
        </p>
      )}
      {item.products.length > 1 && (
        <p className="text-xs text-muted-foreground">
          {t('vulnPage.list.moreProducts', '+{count} more', { count: item.products.length - 1 })}
        </p>
      )}
    </div>
  )
}

function FixCell({ item }: { item: VulnListItem }) {
  const { t } = useTranslation()
  const fix = headlineFixVersion(item)
  if (fix) {
    return (
      <span className="font-mono whitespace-nowrap" title={item.fixed_versions.join(', ')}>
        {toDisplayText(fix, 40)}
      </span>
    )
  }
  return (
    <span className="whitespace-nowrap text-muted-foreground">
      {item.has_fix
        ? t('vulnPage.list.fixKnown', 'Fix known')
        : t('vulnPage.list.noFix', 'No fix yet')}
    </span>
  )
}

function RemediationCell({ item, params }: { item: VulnListItem; params: URLSearchParams }) {
  const { t } = useTranslation()
  const st = remediationState(item)
  const text =
    st === 'closed'
      ? t('vulnPage.list.rem.closed', 'All closed')
      : st === 'untracked'
        ? t('vulnPage.list.rem.untracked', 'Not in a task')
        : st === 'tracked'
          ? t('vulnPage.list.rem.tracked', 'In tasks')
          : t('vulnPage.list.rem.partial', '{done} of {total} in tasks', {
              done: item.in_task,
              total: item.open_findings,
            })
  return (
    <Link
      href={safeHref(rowFindingsHref(item.cve_id, params, { state: 'open' })) ?? '/findings'}
      onClick={(e) => e.stopPropagation()}
      className={cn(
        'whitespace-nowrap hover:underline',
        st !== 'untracked' && 'text-muted-foreground'
      )}
    >
      {text}
    </Link>
  )
}

/** The row as a card at phone width: id and priority, title, signals, reach and fix. */
function MobileVulnRow({ item, onOpen }: { item: VulnListItem; onOpen: () => void }) {
  const { t } = useTranslation()
  const fix = headlineFixVersion(item)
  const title = item.title && item.title !== item.cve_id ? toDisplayText(item.title, 160) : ''
  return (
    <div
      className="cursor-pointer space-y-2 px-3 py-3 hover:bg-muted/50"
      data-slot="vuln-card"
      onClick={(e) => {
        if ((e.target as HTMLElement).closest('button, a[href]')) return
        onOpen()
      }}
    >
      <div className="flex items-start justify-between gap-2">
        <CveLink id={item.cve_id} stopPropagation className="font-medium" />
        <PriorityBadge priorityClass={item.worst_priority || null} />
      </div>
      {title && <p className="line-clamp-2 text-muted-foreground">{title}</p>}
      <SignalsCell item={item} />
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <SeverityBadge severity={item.severity} />
        <span className="tabular-nums">
          {t('vulnPage.list.mobile.epss', 'EPSS {value}', {
            value: formatEpssScore(item.epss_score, 1, '—'),
          })}
        </span>
        <span className="tabular-nums">
          {t('vulnPage.list.mobile.assets', '{count, plural, one {# asset} other {# assets}}', {
            count: item.assets,
          })}
        </span>
        <span className={cn(!fix && 'text-muted-foreground')}>
          {fix
            ? t('vulnPage.list.mobile.fix', 'Fix {version}', { version: toDisplayText(fix, 40) })
            : t('vulnPage.list.noFix', 'No fix yet')}
        </span>
      </div>
    </div>
  )
}
