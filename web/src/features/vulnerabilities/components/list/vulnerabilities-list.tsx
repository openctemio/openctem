'use client'

/**
 * The vulnerabilities list `/vulnerabilities` (server/docs/architecture/vulnerability-page.md,
 * "The list"): one row per CVE across the assets the caller may see, sorted by
 * risk. Every filter lives in the URL (the API's own params), every count on a
 * row opens the findings list that counts it, and a row opens the
 * vulnerability page. Producer and feed text renders as text.
 */

import {
  ListCount,
  ListTitleRow,
  ListViewChanged,
} from '@/features/shared/components/list-title-row'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef, SortingState } from '@tanstack/react-table'
import {
  Bug,
  Download,
  type LucideIcon,
  ListPlus,
  MoreHorizontal,
  RefreshCw,
  RotateCcw,
  ShieldOff,
} from 'lucide-react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { PriorityBadge } from '@/components/ui/priority-badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { useAssetGroupsApi } from '@/features/asset-groups/api/use-asset-groups-api'
import {
  DataTable,
  usePhoneSelectMode,
  type DataTableBulk,
} from '@/features/shared/components/data-table'
import {
  SavedViewsMenu,
  type SavedViewsActions,
} from '@/features/saved-views/components/saved-views-menu'
import { type SavedView, useSavedViews } from '@/features/saved-views/api/use-saved-views'
import { EmptyState } from '@/features/shared/components/empty-state'
import {
  FacetOption,
  FacetPanel,
  FacetSection,
  FacetToggle,
} from '@/features/shared/components/facet-filter-panel'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { FilterSelect } from '@/features/shared/components/filter-select'
import { FilterSheet } from '@/features/shared/components/filter-sheet'
import { MetricStrip, type MetricStripItem } from '@/features/shared/components/metric-strip'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { PageHeader } from '@/features/shared/components/page-header'
import { PageStack } from '@/features/shared/components/page-stack'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { useIsMobile } from '@/hooks/use-mobile'
import { useSearchQuery } from '@/hooks/use-search-query'
import { replaceUrlSearch, useUrlParams, useUrlSettled } from '@/hooks/use-url-param'
import { useSeverityLabel } from '@/hooks/use-scale-labels'
import { formatEpssScore } from '@/lib/epss'
import { SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import type { SeverityLevel } from '@/lib/severity'
import { accessStateOf } from '@/lib/api/access-state'
import { toDisplayText } from '@/lib/untrusted-text'
import { safeHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'
import { useCanReadVulnList, useVulnerabilityList } from '../../api/use-vulnerability-list'
import { vulnerabilityHref } from '../../api/use-cve-exposure'
import { CveLink } from '../cve-link'
import { useVulnActions } from '../actions/use-vuln-actions'
import { AddFilterPanel } from '@/features/shared/components/add-filter-panel'
import {
  AssetsCell,
  EpssCell,
  FixCell,
  KevDueText,
  ProductCell,
  RemediationCell,
  SeverityCell,
  SignalsCell,
  VulnTitleCell,
} from './vuln-list-cells'
import { VulnPhoneCard } from './vuln-phone-card'
import {
  activeFilterCount,
  buildVulnListQuery,
  readEpss,
  readFlag,
  readList,
  readPage,
  readSearch,
  readViewId,
  vulnActionParams,
  readSort,
  readState,
  rowFindingsHref,
  sortToSorting,
  sortingToSort,
  VULN_LIST_EPSS,
  VULN_LIST_PRIORITIES,
  VULN_LIST_SEVERITIES,
  VULN_LIST_SORTS,
  VULN_LIST_SOURCES,
  VULN_LIST_STATES,
  type VulnListFlag,
  type VulnListState,
} from '../../lib/vuln-list'
import type { VulnListItem } from '../../types/list'
import { formatNumber } from '@/lib/app-locale'

const PANEL_ID = 'vulnerability-list-filters'

/**
 * Column priority: when the frame cannot hold every column at its floor (the
 * table measures them, column-sizing.ts), Last seen steps aside first (it
 * stays under Display > Columns), then Remediation, Fix, EPSS, the severity
 * and the reach. The CVE, the title, the signals and the priority always
 * show; the title takes the room left.
 */
const VULN_DROP_ORDER = {
  lastSeen: 1,
  remediation: 2,
  fix: 3,
  epss: 4,
  severity: 5,
  assets: 6,
} as const

// Below 1024 px the toolbar keeps one row by moving the order (the select of
// lowest priority: the column headers sort too) from the toolbar into Add
// filter. Remove when the kit's FilterSelect gets a compact value slot.
const SORT_FOLD_TOOLBAR = 'max-lg:hidden'
const SORT_FOLD_PANEL = 'lg:hidden'

type Patch = Record<string, string | null>

/** One bulk action: a button in the bar or an item of its More. */
interface BulkEntry {
  id: string
  label: string
  icon: LucideIcon
  onSelect: () => void
  disabledReason?: string
}

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
  const { t } = useTranslation()
  const router = useRouter()
  const severityLabel = useSeverityLabel()
  const urlSettled = useUrlSettled()
  const params = useUrlParams()
  const query = useMemo(() => buildVulnListQuery(params), [params])
  const { data, error, isLoading, isValidating, mutate } = useVulnerabilityList(query, urlSettled)
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  // When the rows on screen were read: the table says so once they are old.
  const [readAt, setReadAt] = useState<Date | undefined>(undefined)
  useEffect(() => {
    if (data) setReadAt(new Date())
  }, [data])
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
  const cveSel = readList(params, 'cve_id')
  const viewId = readViewId(params)
  const epss = readEpss(params)
  const flag = (f: VulnListFlag) => readFlag(params, f)
  const filterCount = activeFilterCount(params)
  // The open saved view (read only while one is open: no request otherwise).
  const { views: savedViewList } = useSavedViews('vulnerabilities', !!viewId)
  const openView = savedViewList.find((v) => v.id === viewId)

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
      cve_id: null,
    })
  }, [])

  // Bulk actions on the selected rows: the open findings of their CVEs that
  // the current filters select, resolved by the API as the signed-in person.
  const [selected, setSelected] = useState<VulnListItem[]>([])
  const [selectionKey, setSelectionKey] = useState(0)
  const clearSelection = useCallback(() => {
    setSelected([])
    setSelectionKey((k) => k + 1)
  }, [])
  const actions = useVulnActions(() => {
    clearSelection()
    void mutate()
  })
  const actionParams = useMemo(() => vulnActionParams(params), [params])
  const selection = useMemo(
    () => ({ cveIds: selected.map((r) => r.cve_id), params: actionParams.toString() }),
    [selected, actionParams]
  )
  const canSelect =
    actions.abilities.task ||
    actions.abilities.exception ||
    actions.abilities.retest ||
    actions.abilities.export

  // A saved view lives in the URL as view=<id>; the API applies its filters
  // and params as the viewer, the URL's params on top.
  const openSavedView = useCallback((view: SavedView | null) => {
    replaceUrlSearch(view ? new URLSearchParams({ view: view.id }) : new URLSearchParams())
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
  listChip('cve_id', t('vulnPage.list.chip.cve', 'CVE'), cveSel, (v) => v)
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
        data-testid="vuln-filter-chips"
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
        onClearAll={chips.length > 1 ? clearAll : undefined}
      />
    ) : undefined

  const stateLabel = (s: VulnListState) =>
    ({
      open: t('vulnPage.list.state.open', 'Open'),
      fixed: t('vulnPage.list.state.fixed', 'Fixed'),
      dispositioned: t('vulnPage.list.state.dispositioned', 'Dismissed'),
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

  // `withSelects`: the phone sheet also holds the two toolbar selects (the
  // findings state and the order), so every filter is in one place there.
  // Under 1024 px the toolbar has no room for both selects on one row: the
  // order folds out of the toolbar into Add filter (`SORT_FOLD_*`).
  const sortSection = (
    <FacetSection
      title={t('vulnPage.list.sort.label', 'Sort')}
      selectedCount={sort.key !== 'risk' ? 1 : 0}
      defaultOpen={false}
    >
      {VULN_LIST_SORTS.map((k) => (
        <FacetOption
          key={k}
          label={sortLabel[k]}
          checked={sort.key === k}
          onCheckedChange={(on) => patchUrl({ sort: on && k !== 'risk' ? k : null })}
        />
      ))}
    </FacetSection>
  )
  const facetPanel = (withSelects: boolean) => (
    <FacetPanel activeCount={filterCount} onClearAll={clearAll}>
      {withSelects ? (
        <>
          <FacetSection
            title={t('vulnPage.list.state.label', 'Findings')}
            selectedCount={state !== 'open' ? 1 : 0}
          >
            {VULN_LIST_STATES.map((s) => (
              <FacetOption
                key={s}
                label={stateLabel(s)}
                checked={state === s}
                onCheckedChange={(on) => patchUrl({ state: on && s !== 'open' ? s : null })}
              />
            ))}
          </FacetSection>
          {sortSection}
        </>
      ) : (
        <div data-slot="sort-fold" className={SORT_FOLD_PANEL}>
          {sortSection}
        </div>
      )}
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

  // One line per row. The CVE id is the row's identity: frozen at the start
  // while the table scrolls sideways. The checkbox column is the table's own.
  const columns = useMemo<ColumnDef<VulnListItem>[]>(
    () => [
      {
        id: 'cve',
        header: t('vulnPage.list.col.cve', 'CVE'),
        meta: {
          kind: 'id',
          pin: 'start',
          label: t('vulnPage.list.col.cve', 'CVE'),
        },
        enableSorting: true,
        enableHiding: false,
        cell: ({ row }) => (
          <CveLink
            id={row.original.cve_id}
            stopPropagation
            className="block truncate font-medium"
          />
        ),
      },
      {
        id: 'title',
        header: t('vulnPage.list.col.vulnerability', 'Vulnerability'),
        meta: {
          kind: 'name',
          primary: true,
          label: t('vulnPage.list.col.vulnerability', 'Vulnerability'),
        },
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => <VulnTitleCell item={row.original} />,
      },
      {
        id: 'signals',
        header: t('vulnPage.list.col.signals', 'Exploitation'),
        meta: {
          kind: 'signals',
          label: t('vulnPage.list.col.signals', 'Exploitation'),
        },
        enableSorting: false,
        cell: ({ row }) => <SignalsCell item={row.original} />,
      },
      {
        id: 'priority',
        header: t('vulnPage.list.col.priority', 'Priority'),
        meta: {
          kind: 'priority',
          label: t('vulnPage.list.col.priority', 'Priority'),
        },
        enableSorting: false,
        cell: ({ row }) => <PriorityBadge priorityClass={row.original.worst_priority || null} />,
      },
      {
        id: 'cvss',
        header: t('vulnPage.list.col.severity', 'Severity'),
        meta: {
          kind: 'severity',
          dropOrder: VULN_DROP_ORDER.severity,
          label: t('vulnPage.list.col.severity', 'Severity'),
        },
        enableSorting: true,
        cell: ({ row }) => <SeverityCell item={row.original} />,
      },
      {
        id: 'epss',
        header: t('vulnPage.list.col.epss', 'EPSS'),
        meta: {
          kind: 'number',
          dropOrder: VULN_DROP_ORDER.epss,
          label: t('vulnPage.list.col.epss', 'EPSS'),
        },
        enableSorting: true,
        cell: ({ row }) => <EpssCell item={row.original} />,
      },
      {
        id: 'assets',
        header: t('vulnPage.list.col.assets', 'Assets'),
        meta: {
          kind: 'text',
          dropOrder: VULN_DROP_ORDER.assets,
          sortFirst: 'desc',
          label: t('vulnPage.list.col.assets', 'Assets'),
        },
        enableSorting: true,
        cell: ({ row }) => <AssetsCell item={row.original} params={params} />,
      },
      {
        id: 'product',
        header: t('vulnPage.list.col.product', 'Affected product'),
        meta: {
          kind: 'text',
          label: t('vulnPage.list.col.product', 'Affected product'),
        },
        enableSorting: false,
        cell: ({ row }) => <ProductCell item={row.original} />,
      },
      {
        id: 'fix',
        header: t('vulnPage.list.col.fix', 'Fix'),
        meta: {
          // A version: whole, never cut.
          kind: 'id',
          dropOrder: VULN_DROP_ORDER.fix,
          label: t('vulnPage.list.col.fix', 'Fix'),
        },
        enableSorting: false,
        cell: ({ row }) => <FixCell item={row.original} />,
      },
      {
        id: 'remediation',
        header: t('vulnPage.list.col.remediation', 'Remediation'),
        meta: {
          // A state ("No task", "Task open"): whole, never cut.
          kind: 'status',
          dropOrder: VULN_DROP_ORDER.remediation,
          label: t('vulnPage.list.col.remediation', 'Remediation'),
        },
        enableSorting: false,
        cell: ({ row }) => <RemediationCell item={row.original} params={params} />,
      },
      {
        id: 'findings',
        header: t('vulnPage.list.col.findings', 'Findings'),
        meta: { kind: 'number', label: t('vulnPage.list.col.findings', 'Findings') },
        enableSorting: true,
        cell: ({ row }) => (
          <Link
            href={safeHref(rowFindingsHref(row.original.cve_id, params)) ?? '/findings'}
            onClick={(e) => e.stopPropagation()}
            className="tabular-nums hover:underline"
          >
            {formatNumber(row.original.findings)}
          </Link>
        ),
      },
      {
        id: 'kev_due',
        header: t('vulnPage.list.col.kevDue', 'KEV due'),
        meta: { kind: 'due', label: t('vulnPage.list.col.kevDue', 'KEV due') },
        enableSorting: true,
        cell: ({ row }) => <KevDueText due={row.original.kev_due_date} />,
      },
      {
        id: 'first_seen',
        header: t('vulnPage.list.col.firstSeen', 'First seen'),
        meta: {
          kind: 'datetime-recent',
          label: t('vulnPage.list.col.firstSeen', 'First seen'),
        },
        enableSorting: true,
        cell: ({ row }) => <RelativeTime date={row.original.first_seen_at} />,
      },
      {
        id: 'last_seen',
        header: t('vulnPage.list.col.lastSeen', 'Last seen'),
        meta: {
          kind: 'datetime-recent',
          dropOrder: VULN_DROP_ORDER.lastSeen,
          label: t('vulnPage.list.col.lastSeen', 'Last seen'),
        },
        enableSorting: true,
        cell: ({ row }) => <RelativeTime date={row.original.last_seen_at} />,
      },
    ],
    [t, params]
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

  // The toolbar row after the search: Add filter (it never changes size),
  // then the list's two fixed selects, each in a box as wide as its longest
  // value, so choosing a value moves nothing.
  const toolbarStart = (
    <>
      <AddFilterPanel>{facetPanel(false)}</AddFilterPanel>
      <FilterSelect<VulnListState>
        label={t('vulnPage.list.state.label', 'Findings')}
        value={state}
        clearable={false}
        foldLabel
        // On a phone both selects live in the Filters sheet: the toolbar's
        // second line holds the chips, which must not push a select along.
        className="max-md:hidden"
        options={VULN_LIST_STATES.map((s) => ({ value: s, label: stateLabel(s) }))}
        onChange={(v) => patchUrl({ state: v && v !== 'open' ? v : null })}
      />
      <FilterSelect<string>
        label={t('vulnPage.list.sort.label', 'Sort')}
        value={sort.key}
        clearable={false}
        foldLabel
        className={SORT_FOLD_TOOLBAR}
        options={VULN_LIST_SORTS.map((s) => ({ value: s, label: sortLabel[s] }))}
        onChange={(v) => patchUrl({ sort: v && v !== 'risk' ? v : null })}
      />
    </>
  )

  // Which view this is. A saved view is "modified" when the link carries
  // anything beside it; the list itself ("All vulnerabilities") when a
  // filter, search text, another findings state or another order is on.
  const searching = readSearch(params) !== ''
  const narrowed = filterCount > 0 || searching || state !== 'open'
  const viewModified = viewId
    ? Array.from(params.keys()).some((k) => !['view', 'page', 'per_page'].includes(k))
    : narrowed || sort.key !== 'risk' || sort.flipped
  const viewTitle = openView?.name ?? t('vulnPage.list.viewAll', 'All vulnerabilities')
  const resetView = useCallback(() => {
    setSearchInput('')
    replaceUrlSearch(new URLSearchParams(viewId ? { view: viewId } : {}))
  }, [viewId])
  const clearFilters = useCallback(() => {
    setSearchInput('')
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
      cve_id: null,
      state: null,
      q: null,
    })
  }, [])
  const [savedViewsActions, setSavedViewsActions] = useState<SavedViewsActions | null>(null)
  const openSaveView = () => savedViewsActions?.openSave()
  const saveViewChanges = () => void savedViewsActions?.saveChanges()
  const canUpdateView = !!openView?.is_owner
  const saveViewLabel = t('common.listView.save', 'Save view')
  const saveChangesLabel = t('confirm.savedView.saveChanges', 'Save changes')
  const saveAsNewLabel = t('confirm.savedView.saveAsNew', 'Save as new view…')

  const toolbarEnd = (
    <SavedViewsMenu
      page="vulnerabilities"
      actionsRef={setSavedViewsActions}
      activeId={viewId}
      modified={!!viewId && viewModified}
      onSelect={openSavedView}
      onDiscard={resetView}
    />
  )

  // The bulk bar: at most two direct actions, the rest under More, each only
  // with its permission (the API checks again). With no bulk permission there
  // is no checkbox column.
  const bulkEntries: BulkEntry[] = [
    ...(actions.abilities.task
      ? [
          {
            id: 'task',
            label: t('vulnPage.list.bulk.task', 'Create task'),
            icon: ListPlus,
            onSelect: () =>
              void actions.createTask(
                selection,
                selected.length === 1
                  ? t('vulnPage.task.title', 'Fix {cve}', { cve: selected[0].cve_id })
                  : t('vulnPage.list.bulk.taskTitle', 'Fix {count} vulnerabilities', {
                      count: selected.length,
                    })
              ),
          },
        ]
      : []),
    ...(actions.abilities.exception
      ? [
          {
            id: 'exception',
            label: t('vulnPage.list.bulk.exception', 'Accept risk'),
            icon: ShieldOff,
            onSelect: () => actions.requestException(selection),
          },
        ]
      : []),
    ...(actions.abilities.retest
      ? [
          {
            id: 'retest',
            label: t('vulnPage.list.bulk.retest', 'Retest'),
            icon: RotateCcw,
            onSelect: () => actions.retest(selection),
          },
        ]
      : []),
    ...(actions.abilities.export
      ? [
          {
            id: 'export',
            label: t('vulnPage.list.bulk.export', 'Export'),
            icon: Download,
            disabledReason: actions.busy
              ? t('vulnPage.list.bulk.busy', 'Wait for the current export to finish.')
              : undefined,
            onSelect: () => void actions.exportCsv(actionParams, selection.cveIds),
          },
        ]
      : []),
  ]
  const vulnBulk: DataTableBulk<VulnListItem> | undefined = canSelect
    ? {
        rowLabel: (r) => r.cve_id,
        checkboxLabel: (r) => t('vulnPage.list.selectRow', 'Select {cve}', { cve: r.cve_id }),
        actions: (
          <>
            {bulkEntries.slice(0, 2).map((a) => (
              <Button
                key={a.id}
                size="sm"
                variant="ghost"
                disabled={!!a.disabledReason}
                title={a.disabledReason}
                onClick={a.onSelect}
              >
                <a.icon aria-hidden />
                {a.label}
              </Button>
            ))}
          </>
        ),
        more: bulkEntries.length > 2 ? bulkEntries.slice(2) : undefined,
        onSelectionChange: (sel) => setSelected(sel?.kind === 'ids' ? sel.rows : []),
      }
    : undefined

  // Phone cards have no header checkbox: "Select" starts the title row's More.
  const isPhone = useIsMobile()
  const phoneSelect = usePhoneSelectMode(isPhone && !!vulnBulk)

  const refreshLabel = t('vulnPage.list.refresh', 'Refresh')
  const refreshButton = (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="outline"
          size="icon"
          onClick={() => void mutate()}
          disabled={isValidating}
          aria-label={refreshLabel}
        >
          <RefreshCw
            className={cn('h-4 w-4', isValidating && 'animate-spin motion-reduce:animate-none')}
            aria-hidden
          />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{refreshLabel}</TooltipContent>
    </Tooltip>
  )
  const exportHint = t(
    'vulnPage.list.exportHint',
    'The findings behind the rows under the current filters, one per line with its asset'
  )
  const exportOff = actions.busy || total === 0
  const exportButton = actions.abilities.export ? (
    <Button
      variant="outline"
      size="sm"
      disabled={exportOff}
      onClick={() => void actions.exportCsv(actionParams)}
      title={exportHint}
    >
      <Download aria-hidden />
      {t('vulnPage.list.export', 'Export CSV')}
    </Button>
  ) : null
  // Under 42rem of row width (and on a phone) the row's actions fold into
  // More: Select first, then what a changed view offers, then Export.
  const moreItems: ActionMenuEntry[] = [
    ...(phoneSelect.item ? [phoneSelect.item] : []),
    ...(viewModified
      ? [
          ...(canUpdateView
            ? [{ id: 'view-save-changes', label: saveChangesLabel, onSelect: saveViewChanges }]
            : []),
          {
            id: 'view-save',
            label: canUpdateView ? saveAsNewLabel : saveViewLabel,
            onSelect: openSaveView,
          },
          { id: 'view-reset', label: t('common.listView.reset', 'Reset'), onSelect: resetView },
        ]
      : []),
    ...(actions.abilities.export
      ? [
          {
            id: 'export-csv',
            label: t('vulnPage.list.export', 'Export CSV'),
            section: 'export',
            disabledReason: actions.busy
              ? t('vulnPage.list.bulk.busy', 'Wait for the current export to finish.')
              : total === 0
                ? t('vulnPage.list.exportEmpty', 'There is nothing to export.')
                : undefined,
            onSelect: () => void actions.exportCsv(actionParams),
          },
        ]
      : []),
  ]
  const moreMenu =
    moreItems.length > 0 ? (
      <ActionMenu
        title={viewTitle}
        label={t('common.actionMenu.label', 'Actions for {name}', { name: viewTitle })}
        items={moreItems}
        trigger={
          <Button
            variant="outline"
            size="icon"
            aria-label={t('common.actionMenu.more', 'More actions')}
          >
            <MoreHorizontal className="h-4 w-4" aria-hidden />
          </Button>
        }
      />
    ) : null

  const titleRow = (
    <ListTitleRow
      data-testid="vuln-list-title-row"
      className="@container/actions"
      title={viewTitle}
      count={<ListCount total={total} loading={!data} label={resultLabel} />}
      start={
        <ListViewChanged
          changed={viewModified}
          // On a row under 42rem the two buttons are in the row's More.
          actionsClassName="hidden @2xl/actions:flex"
          onSave={openSaveView}
          onSaveChanges={canUpdateView ? saveViewChanges : undefined}
          onReset={resetView}
        />
      }
    >
      {refreshButton}
      {exportButton && <div className="hidden @2xl/actions:block">{exportButton}</div>}
      {moreMenu && <div className="@2xl/actions:hidden">{moreMenu}</div>}
    </ListTitleRow>
  )

  // A failed read with rows on screen keeps the rows (the table says how old
  // they are and offers a refresh); without rows the error takes their place.
  const noAccess = accessStateOf(error) === 'no_access'
  const firstRun = !!data && !error && total === 0 && !narrowed && !viewId
  const readError = error && !data ? error : undefined

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
        <MetricStrip items={strip} loading={!data && !error} listFirst />
        {titleRow}
        {noAccess ? (
          <NoAccessState title={t('vulnPage.list.subject', 'the vulnerabilities list')} />
        ) : (
          <DataTable
            columns={columns}
            // Widths follow the header and the rows on screen (column-sizing.ts).
            columnSizing="content"
            data={rows}
            error={readError}
            onRetry={() => void mutate()}
            errorTitle={t('vulnPage.list.subject', 'the vulnerabilities list')}
            showSearch={false}
            search={{
              value: searchInput,
              onChange: setSearchInput,
              placeholder: t('vulnPage.list.searchPlaceholder', 'Search CVE or title…'),
              label: t('vulnPage.list.searchLabel', 'Search vulnerabilities'),
            }}
            // One filter entry per width: Add filter from 768, this button
            // (joined to the search field) on a phone, where it opens the sheet.
            filterToggle={{
              open: false,
              onToggle: () => setFilterSheetOpen(true),
              onOpenSheet: () => setFilterSheetOpen(true),
              activeCount: filterCount + (state !== 'open' ? 1 : 0),
              controlsId: PANEL_ID,
              label: t('vulnPage.list.filtersTitle', 'Vulnerability filters'),
              sheetOnly: true,
            }}
            toolbarStart={toolbarStart}
            toolbarEnd={toolbarEnd}
            toolbarBelow={chipsRow}
            getRowId={(r) => r.cve_id}
            bulk={vulnBulk}
            selectMode={phoneSelect.selectMode}
            resetSelectionKey={`${actionParams.toString()}#${selectionKey}`}
            showSelectionCount={false}
            manualPagination
            rowCount={total}
            pageCount={Math.max(1, data?.total_pages ?? 1)}
            pagination={pagination}
            onPaginationChange={onPaginationChange}
            sorting={sorting}
            onSortingChange={onSortingChange}
            isLoading={isLoading}
            isRefreshing={isValidating && !isLoading}
            refreshingLabel={t('vulnPage.list.refreshing', 'Refreshing vulnerabilities')}
            // A first run has nothing to search, filter or arrange.
            showToolbar={!firstRun}
            staleAt={readAt}
            refreshFailed={!!error && !!data}
            onRefresh={() => void mutate()}
            onRowClick={(r) => router.push(vulnerabilityHref(r.cve_id))}
            initialColumnVisibility={{
              product: false,
              findings: false,
              kev_due: false,
              first_seen: false,
            }}
            mobileRow={(r, sel) => (
              <VulnPhoneCard
                item={r}
                selection={sel}
                onOpen={() => router.push(vulnerabilityHref(r.cve_id))}
              />
            )}
            paginationNoun={t('vulnPage.list.noun', 'vulnerabilities')}
            isFiltered={narrowed || !!viewId}
            onClearFilters={clearFilters}
            emptyState={{
              nothingYet: (
                <EmptyState
                  icon={Bug}
                  title={t(
                    'vulnPage.list.empty.title',
                    'No open vulnerabilities on the assets you can see'
                  )}
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
              ),
              noMatch: {
                title: t(
                  'vulnPage.list.empty.filteredTitle',
                  'No vulnerability matches these filters'
                ),
                hint: t(
                  'vulnPage.list.empty.filteredHint',
                  'Remove a filter, clear the search or switch the findings to All.'
                ),
              },
            }}
          />
        )}
        <FilterSheet
          open={filterSheetOpen}
          onOpenChange={setFilterSheetOpen}
          title={t('vulnPage.list.filtersTitle', 'Vulnerability filters')}
        >
          {facetPanel(true)}
        </FilterSheet>
        {actions.dialogs}
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
