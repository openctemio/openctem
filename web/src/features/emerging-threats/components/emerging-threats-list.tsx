'use client'

/**
 * The emerging-threat triage queue (research/463): a strip of counts that
 * filter, one toolbar (state, search, filter panel, display), one compact row
 * per threat ranked by the exploitation-weighted score, and a drawer with the
 * why and the actions. Server text (products) is rendered as plain text.
 */

import { useCallback, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { CheckCheck, ExternalLink, PanelRight, RotateCcw, Siren, Wrench } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission } from '@/lib/permissions'
import { DataTable } from '@/features/shared/components/data-table'
import {
  DataTableRowActions,
  type RowAction,
} from '@/features/shared/components/data-table-row-actions'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import {
  FacetOption,
  FacetPanel,
  FacetSection,
  FacetToggle,
} from '@/features/shared/components/facet-filter-panel'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import {
  FilterPanelSlot,
  useFilterPanelOpen,
} from '@/features/shared/components/filter-panel-layout'
import { FilterSelect } from '@/features/shared/components/filter-select'
import { FilterSheet } from '@/features/shared/components/filter-sheet'
import { MetricStrip, type MetricStripItem } from '@/features/shared/components/metric-strip'
import { PageStack } from '@/features/shared/components/page-stack'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { setAlertState, useEmergingThreats, useRevalidateEmergingThreats } from '../api'
import {
  LEVELS,
  STATE_FILTERS,
  type AlertLevel,
  type AlertTier,
  type EmergingThreatSummary,
  type StateFilter,
  type TargetState,
} from '../types'
import {
  AffectedCell,
  ExploitBadges,
  LastChangeCell,
  LevelBadge,
  ScoreCell,
  StateBadge,
  ThreatCell,
} from './bits'
import { EmergingThreatSheet } from './emerging-threat-sheet'
import { useSearchQuery } from '@/hooks/use-search-query'
import { replaceUrlSearch, useUrlParams, useUrlSettled } from '@/hooks/use-url-param'
import { parseListQuery, writeListQuery, type ListQuery } from '../url-filters'

const TIERS: AlertTier[] = ['confirmed', 'possible']
const PANEL_ID = 'emerging-threat-filters'
const detailHref = (id: string) => `/emerging-threats/${id}`

export function EmergingThreatsList() {
  const { t } = useTranslation()
  const router = useRouter()
  const revalidate = useRevalidateEmergingThreats()
  // Every filter lives in the URL (url-filters.ts), so a view can be linked
  // to: a dashboard level opens the list filtered to it.
  const params = useUrlParams()
  const urlSettled = useUrlSettled()
  const query = useMemo(() => parseListQuery(params), [params])
  const { level, state, tier, internetOnly, kevOnly } = query
  const searchInput = query.search
  const search = useSearchQuery(searchInput).term
  const pagination = { pageIndex: query.page - 1, pageSize: query.perPage }
  const [panelOpen, setPanelOpen] = useFilterPanelOpen('emerging-threats.filters')
  const [sheetOpen, setSheetOpen] = useState(false)
  const [openId, setOpenId] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)

  /** Writes filters to the URL; any filter change goes back to the first page. */
  const update = (patch: Partial<ListQuery>) => {
    const current = parseListQuery(new URLSearchParams(window.location.search))
    const next = { ...current, page: 1, ...patch }
    replaceUrlSearch(writeListQuery(new URLSearchParams(window.location.search), next))
  }
  const setLevel = (v: AlertLevel | undefined) => update({ level: v })
  const setTier = (v: AlertTier | undefined) => update({ tier: v })
  const setPagination = (p: { pageIndex: number; pageSize: number }) =>
    update(
      p.pageSize !== query.perPage
        ? { perPage: p.pageSize, page: 1 }
        : { page: p.pageIndex + 1, perPage: p.pageSize }
    )

  const { data, error, isLoading, mutate } = useEmergingThreats(
    { level, state, tier, internetOnly, kevOnly, search, page: query.page, perPage: query.perPage },
    undefined,
    urlSettled
  )
  const rows = useMemo(() => data?.data ?? [], [data])
  const summary = data?.summary

  // Every tile is a one-click filter of the list below (research/463 D2).
  const strip: MetricStripItem[] = [
    {
      key: 'immediate',
      label: t('emergingThreats.summary.immediate'),
      description: t('emergingThreats.summary.immediateHint'),
      value: summary?.immediate ?? 0,
      tone: 'danger',
      active: level === 'immediate',
      onClick: () => setLevel(level === 'immediate' ? undefined : 'immediate'),
    },
    {
      key: 'untriaged',
      label: t('emergingThreats.summary.untriaged'),
      description: t('emergingThreats.summary.untriagedHint'),
      value: summary?.new ?? 0,
      tone: 'warning',
      active: state === 'new',
      onClick: () => update({ state: state === 'new' ? 'open' : 'new' }),
    },
    {
      key: 'digest',
      label: t('emergingThreats.summary.digest'),
      description: t('emergingThreats.summary.digestHint'),
      value: summary?.digest ?? 0,
      active: level === 'digest',
      onClick: () => setLevel(level === 'digest' ? undefined : 'digest'),
    },
    {
      key: 'kev',
      label: t('emergingThreats.summary.kev'),
      description: t('emergingThreats.summary.kevHint'),
      value: summary?.kev ?? 0,
      tone: 'danger',
      active: kevOnly,
      onClick: () => update({ kevOnly: !kevOnly }),
    },
    {
      key: 'internet',
      label: t('emergingThreats.summary.internetFacing'),
      description: t('emergingThreats.summary.internetHint'),
      value: summary?.internet_facing ?? 0,
      tone: 'warning',
      active: internetOnly,
      onClick: () => update({ internetOnly: !internetOnly }),
    },
  ]

  const levelLabel = (l: AlertLevel) => t(`emergingThreats.level.${l}`)
  const tierLabel = (v: AlertTier) => t(`emergingThreats.tier.${v}`)
  const activeCount = [level, tier, internetOnly, kevOnly].filter(Boolean).length
  const clearPanel = () =>
    update({ level: undefined, tier: undefined, internetOnly: false, kevOnly: false })

  const facetPanel = (
    <FacetPanel activeCount={activeCount} onClearAll={clearPanel}>
      <FacetSection title={t('emergingThreats.filter.level')} selectedCount={level ? 1 : 0}>
        {LEVELS.map((l) => (
          <FacetOption
            key={l}
            label={levelLabel(l)}
            checked={level === l}
            onCheckedChange={(on) => setLevel(on ? l : undefined)}
          />
        ))}
      </FacetSection>
      <FacetSection title={t('emergingThreats.filter.tier')} selectedCount={tier ? 1 : 0}>
        {TIERS.map((v) => (
          <FacetOption
            key={v}
            label={tierLabel(v)}
            checked={tier === v}
            onCheckedChange={(on) => setTier(on ? v : undefined)}
          />
        ))}
      </FacetSection>
      <div className="px-1">
        <FacetToggle
          label={t('emergingThreats.filter.kevOnly')}
          description={t('emergingThreats.filter.kevOnlyHelp')}
          checked={kevOnly}
          onCheckedChange={(v) => update({ kevOnly: v })}
        />
        <FacetToggle
          label={t('emergingThreats.filter.internetOnly')}
          description={t('emergingThreats.filter.internetOnlyHelp')}
          checked={internetOnly}
          onCheckedChange={(v) => update({ internetOnly: v })}
        />
      </div>
    </FacetPanel>
  )

  const chip = (key: string, text: string, onRemove: () => void) => (
    <RemovableFilterChip
      key={key}
      text={text}
      onRemove={onRemove}
      removeLabel={t('emergingThreats.chip.remove', undefined, { filter: text })}
    />
  )
  const chips = [
    level &&
      chip('level', t('emergingThreats.chip.level', undefined, { value: levelLabel(level) }), () =>
        setLevel(undefined)
      ),
    tier &&
      chip('tier', t('emergingThreats.chip.tier', undefined, { value: tierLabel(tier) }), () =>
        setTier(undefined)
      ),
    kevOnly && chip('kev', t('emergingThreats.chip.kev'), () => update({ kevOnly: false })),
    internetOnly &&
      chip('internet', t('emergingThreats.chip.internet'), () => update({ internetOnly: false })),
  ].filter((c): c is React.ReactElement => Boolean(c))

  const move = useCallback(
    async (row: EmergingThreatSummary, target: TargetState) => {
      setBusyId(row.id)
      try {
        await setAlertState(row.id, target)
        toast.success(t(`emergingThreats.toast.${target}`))
        await revalidate()
      } catch (err) {
        toast.error(getErrorMessage(err))
      } finally {
        setBusyId(null)
      }
    },
    [t, revalidate]
  )

  const rowActions = useCallback(
    (row: EmergingThreatSummary): RowAction[] => {
      const busy = busyId === row.id
      const open =
        row.state === 'new' || row.state === 'acknowledged' || row.state === 'remediating'
      const actions: RowAction[] = [
        {
          label: t('emergingThreats.actions.view'),
          icon: PanelRight,
          onClick: () => setOpenId(row.id),
        },
        {
          label: t('emergingThreats.actions.openPage'),
          icon: ExternalLink,
          onClick: () => router.push(detailHref(row.id)),
        },
      ]
      if (row.state === 'new') {
        actions.push({
          label: t('emergingThreats.actions.acknowledge'),
          icon: CheckCheck,
          onClick: () => void move(row, 'acknowledged'),
          disabled: busy,
          permission: Permission.FindingsTriage,
          separatorBefore: true,
        })
      }
      if (row.state === 'new' || row.state === 'acknowledged') {
        actions.push({
          label: t('emergingThreats.actions.remediating'),
          icon: Wrench,
          onClick: () => void move(row, 'remediating'),
          disabled: busy,
          permission: Permission.FindingsTriage,
          separatorBefore: row.state !== 'new',
        })
      }
      if (row.state !== 'new') {
        actions.push({
          label: t('emergingThreats.actions.reopen'),
          icon: RotateCcw,
          onClick: () => void move(row, 'new'),
          disabled: busy,
          permission: Permission.FindingsTriage,
          separatorBefore: !open,
        })
      }
      return actions
    },
    [t, busyId, router, move]
  )

  const columns = useMemo<ColumnDef<EmergingThreatSummary>[]>(
    () => [
      {
        id: 'vuln',
        header: t('emergingThreats.col.threat'),
        cell: ({ row }) => <ThreatCell alert={row.original} />,
      },
      {
        id: 'level',
        header: t('emergingThreats.col.level'),
        cell: ({ row }) => <LevelBadge level={row.original.level} />,
      },
      {
        id: 'ets',
        header: t('emergingThreats.col.ets'),
        meta: { hideBelow: 860 },
        cell: ({ row }) => (
          <ScoreCell ets={row.original.ets} breakdown={row.original.ets_breakdown} />
        ),
      },
      {
        id: 'exploit',
        header: t('emergingThreats.col.exploit'),
        cell: ({ row }) => (
          <ExploitBadges
            inKev={row.original.in_kev}
            ransomware={row.original.kev_ransomware}
            epss={row.original.epss}
          />
        ),
      },
      {
        id: 'affected',
        header: t('emergingThreats.col.affected'),
        cell: ({ row }) => (
          <AffectedCell
            confirmed={row.original.confirmed_assets}
            possible={row.original.possible_assets}
            internet={row.original.internet_facing_assets}
            critical={row.original.critical_assets ?? 0}
          />
        ),
      },
      {
        id: 'state',
        header: t('emergingThreats.col.state'),
        cell: ({ row }) => <StateBadge state={row.original.state} />,
      },
      {
        id: 'event',
        header: t('emergingThreats.col.lastEvent'),
        meta: { hideBelow: 1000 },
        cell: ({ row }) => (
          <LastChangeCell kind={row.original.last_event_kind} at={row.original.event_at} />
        ),
      },
      {
        id: 'actions',
        header: '',
        enableHiding: false,
        cell: ({ row }) => (
          <div onClick={(e) => e.stopPropagation()}>
            <DataTableRowActions
              actions={rowActions(row.original)}
              label={t('emergingThreats.actions.menu', undefined, { vulnId: row.original.vuln_id })}
            />
          </div>
        ),
      },
    ],
    [t, rowActions]
  )

  const stateOptions = STATE_FILTERS.filter((s) => s !== 'open').map((s) => ({
    value: s,
    label: s === 'all' ? t('emergingThreats.filter.stateAll') : t(`emergingThreats.state.${s}`),
  }))

  const neverAny =
    !isLoading &&
    !error &&
    rows.length === 0 &&
    (summary?.open ?? 0) === 0 &&
    !level &&
    !tier &&
    !internetOnly &&
    !kevOnly &&
    !searchInput &&
    state === 'open'

  return (
    <PageStack>
      <MetricStrip items={strip} loading={isLoading && !data} />

      {neverAny ? (
        <EmptyState
          icon={Siren}
          title={t('emergingThreats.empty.title')}
          description={t('emergingThreats.empty.description')}
          card
        />
      ) : (
        <div className="flex items-start">
          <FilterPanelSlot open={panelOpen} id={PANEL_ID} label={t('emergingThreats.filter.panel')}>
            {facetPanel}
          </FilterPanelSlot>
          <div className="min-w-0 flex-1">
            <DataTable
              columns={columns}
              data={rows}
              showSearch={false}
              search={{
                value: searchInput,
                onChange: (v: string) => update({ search: v }),
                placeholder: t('emergingThreats.filter.searchPlaceholder'),
                label: t('emergingThreats.filter.search'),
              }}
              filterToggle={{
                open: panelOpen,
                onToggle: () => setPanelOpen((o) => !o),
                onOpenSheet: () => setSheetOpen(true),
                activeCount,
                controlsId: PANEL_ID,
              }}
              toolbarStart={
                <FilterSelect<StateFilter>
                  label={t('emergingThreats.filter.state')}
                  value={state}
                  allValue="open"
                  allLabel={t('emergingThreats.filter.stateOpen')}
                  options={stateOptions}
                  onChange={(v) => update({ state: (v || 'open') as StateFilter })}
                />
              }
              toolbarBelow={
                chips.length > 0 ? (
                  <FilterChipsRow
                    label={t('emergingThreats.filter.active')}
                    chips={chips}
                    end={t('emergingThreats.count', undefined, { count: data?.total ?? 0 })}
                  />
                ) : undefined
              }
              isLoading={isLoading && !data}
              errorState={
                error ? (
                  <ErrorState
                    title={t('emergingThreats.loadError')}
                    error={error}
                    onRetry={() => void mutate()}
                  />
                ) : undefined
              }
              manualPagination
              rowCount={data?.total ?? 0}
              pageCount={data ? Math.max(1, data.total_pages) : 1}
              pagination={pagination}
              onPaginationChange={setPagination}
              getRowId={(r) => r.id}
              onRowClick={(r) => setOpenId(r.id)}
              defaultDensity="compact"
              emptyMessage={t('emergingThreats.empty.title')}
              emptyDescription={t('emergingThreats.empty.description')}
            />
          </div>
        </div>
      )}

      <FilterSheet
        open={sheetOpen}
        onOpenChange={setSheetOpen}
        title={t('emergingThreats.filter.panel')}
        resultLabel={t('emergingThreats.filter.show', undefined, { count: data?.total ?? 0 })}
      >
        {facetPanel}
      </FilterSheet>

      <EmergingThreatSheet alertId={openId} onClose={() => setOpenId(null)} />
    </PageStack>
  )
}
