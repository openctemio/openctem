'use client'

/**
 * The emerging-threat list: summary strip, filters, and a server-paged table
 * of alerts ranked by exploitation-weighted score. Server text (titles) is
 * rendered as plain text.
 */

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { Siren } from 'lucide-react'
import Link from '@/components/link'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { DataTable } from '@/features/shared/components/data-table'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { ListToolbar } from '@/features/shared/components/list-toolbar'
import { MetricStrip, type MetricStripItem } from '@/features/shared/components/metric-strip'
import { PageStack } from '@/features/shared/components/page-stack'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { useEmergingThreats } from '../api'
import {
  LEVELS,
  STATE_FILTERS,
  type AlertLevel,
  type AlertTier,
  type EmergingThreatSummary,
  type StateFilter,
} from '../types'
import {
  EtsCell,
  ExploitBadges,
  LevelBadge,
  StateBadge,
  useDateLocale,
  useEventKindLabel,
} from './bits'
import { useSearchQuery } from '@/hooks/use-search-query'
import { replaceUrlSearch, useUrlParams, useUrlSettled } from '@/hooks/use-url-param'
import { parseListQuery, writeListQuery, type ListQuery } from '../url-filters'

const ALL = 'all'

export function EmergingThreatsList() {
  const { t } = useTranslation()
  const router = useRouter()
  const dateLocale = useDateLocale()
  const eventLabel = useEventKindLabel()
  // Every filter lives in the URL (url-filters.ts), so a view can be linked
  // to: a dashboard level opens the list filtered to it.
  const params = useUrlParams()
  const urlSettled = useUrlSettled()
  const query = useMemo(() => parseListQuery(params), [params])
  const { level: levelFilter, state, tier: tierFilter, internetOnly } = query
  const level: AlertLevel | typeof ALL = levelFilter ?? ALL
  const tier: AlertTier | typeof ALL = tierFilter ?? ALL
  const searchInput = query.search
  const search = useSearchQuery(searchInput).term
  const pagination = { pageIndex: query.page - 1, pageSize: query.perPage }

  /** Writes filters to the URL; any filter change goes back to the first page. */
  const update = (patch: Partial<ListQuery>) => {
    const current = parseListQuery(new URLSearchParams(window.location.search))
    const next = { ...current, page: 1, ...patch }
    replaceUrlSearch(writeListQuery(new URLSearchParams(window.location.search), next))
  }
  const setLevel = (v: AlertLevel | typeof ALL) => update({ level: v === ALL ? undefined : v })
  const setState = (v: StateFilter) => update({ state: v })
  const setTier = (v: AlertTier | typeof ALL) => update({ tier: v === ALL ? undefined : v })
  const setInternetOnly = (v: boolean) => update({ internetOnly: v })
  const setSearchInput = (v: string) => update({ search: v })
  const setPagination = (p: { pageIndex: number; pageSize: number }) =>
    update(
      p.pageSize !== query.perPage
        ? { perPage: p.pageSize, page: 1 }
        : { page: p.pageIndex + 1, perPage: p.pageSize }
    )

  const { data, error, isLoading, mutate } = useEmergingThreats(
    {
      level: levelFilter,
      state,
      tier: tierFilter,
      internetOnly,
      search,
      page: query.page,
      perPage: query.perPage,
    },
    undefined,
    urlSettled
  )

  const rows = useMemo(() => data?.data ?? [], [data])
  const summary = data?.summary

  // Every tile is a filter: the level tiles pick that level, Open clears the
  // level and internet-facing filters, Internet-facing toggles its own.
  const toggleLevel = (target: AlertLevel) => setLevel(level === target ? ALL : target)
  const strip: MetricStripItem[] = [
    {
      key: 'open',
      label: t('emergingThreats.summary.open'),
      value: summary?.open ?? 0,
      active: level === ALL && !internetOnly && state === 'open',
      onClick: () => update({ level: undefined, internetOnly: false, state: 'open' }),
    },
    {
      key: 'immediate',
      label: t('emergingThreats.summary.immediate'),
      value: summary?.immediate ?? 0,
      tone: 'danger',
      active: level === 'immediate',
      onClick: () => toggleLevel('immediate'),
    },
    {
      key: 'digest',
      label: t('emergingThreats.summary.digest'),
      value: summary?.digest ?? 0,
      active: level === 'digest',
      onClick: () => toggleLevel('digest'),
    },
    {
      key: 'listed',
      label: t('emergingThreats.summary.listed'),
      value: summary?.listed ?? 0,
      active: level === 'listed',
      onClick: () => toggleLevel('listed'),
    },
    {
      key: 'internet',
      label: t('emergingThreats.summary.internetFacing'),
      value: summary?.internet_facing ?? 0,
      tone: 'warning',
      active: internetOnly,
      onClick: () => setInternetOnly(!internetOnly),
    },
  ]

  const columns = useMemo<ColumnDef<EmergingThreatSummary>[]>(
    () => [
      {
        id: 'vuln',
        header: t('emergingThreats.col.threat'),
        cell: ({ row }) => (
          <div className="min-w-0 max-w-md">
            <Link
              href={`/emerging-threats/${row.original.id}`}
              className="font-mono text-sm font-medium hover:underline"
              onClick={(e) => e.stopPropagation()}
            >
              {row.original.vuln_id}
            </Link>
            {row.original.title && (
              <p className="truncate text-sm text-muted-foreground">{row.original.title}</p>
            )}
          </div>
        ),
      },
      {
        id: 'level',
        header: t('emergingThreats.col.level'),
        cell: ({ row }) => <LevelBadge level={row.original.level} />,
      },
      {
        id: 'ets',
        header: t('emergingThreats.col.ets'),
        cell: ({ row }) => <EtsCell ets={row.original.ets} />,
      },
      {
        id: 'tier',
        header: t('emergingThreats.col.tier'),
        cell: ({ row }) => (
          <span className="text-sm">{t(`emergingThreats.tier.${row.original.tier}`)}</span>
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
          <span className="whitespace-nowrap text-sm tabular-nums">
            {t('emergingThreats.affectedCounts', undefined, {
              confirmed: row.original.confirmed_assets,
              possible: row.original.possible_assets,
              internet: row.original.internet_facing_assets,
            })}
          </span>
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
        cell: ({ row }) => (
          <div className="text-sm">
            {row.original.last_event_kind && <p>{eventLabel(row.original.last_event_kind)}</p>}
            <RelativeTime date={row.original.event_at} />
          </div>
        ),
      },
    ],
    [t, eventLabel, dateLocale]
  )

  return (
    <PageStack>
      <MetricStrip items={strip} loading={isLoading && !data} />

      <ListToolbar
        search={{
          value: searchInput,
          onChange: setSearchInput,
          placeholder: t('emergingThreats.filter.searchPlaceholder'),
          label: t('emergingThreats.filter.search'),
        }}
        start={
          <>
            <FilterSelect
              id="et-level"
              label={t('emergingThreats.filter.level')}
              value={level}
              onChange={(v) => setLevel(v as AlertLevel | typeof ALL)}
              options={[
                [ALL, t('emergingThreats.filter.allLevels')],
                ...LEVELS.map((l): [string, string] => [l, t(`emergingThreats.level.${l}`)]),
              ]}
            />
            <FilterSelect
              id="et-state"
              label={t('emergingThreats.filter.state')}
              value={state}
              onChange={(v) => setState(v as StateFilter)}
              options={STATE_FILTERS.map((s): [string, string] => [
                s,
                s === 'open'
                  ? t('emergingThreats.filter.stateOpen')
                  : s === 'all'
                    ? t('emergingThreats.filter.stateAll')
                    : t(`emergingThreats.state.${s}`),
              ])}
            />
            <FilterSelect
              id="et-tier"
              label={t('emergingThreats.filter.tier')}
              value={tier}
              onChange={(v) => setTier(v as AlertTier | typeof ALL)}
              options={[
                [ALL, t('emergingThreats.filter.allTiers')],
                ['confirmed', t('emergingThreats.tier.confirmed')],
                ['possible', t('emergingThreats.tier.possible')],
              ]}
            />
            <div className="flex h-9 items-center gap-2">
              <Switch
                id="et-internet"
                checked={internetOnly}
                onCheckedChange={(v) => setInternetOnly(v)}
              />
              <Label htmlFor="et-internet" className="text-sm">
                {t('emergingThreats.filter.internetOnly')}
              </Label>
            </div>
          </>
        }
      />

      {error ? (
        <ErrorState
          title={t('emergingThreats.loadError')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : !isLoading && rows.length === 0 ? (
        <EmptyState
          icon={Siren}
          title={t('emergingThreats.empty.title')}
          description={t('emergingThreats.empty.description')}
          card
        />
      ) : (
        <DataTable
          columns={columns}
          data={rows}
          showSearch={false}
          manualPagination
          rowCount={data?.total ?? 0}
          pageCount={data ? Math.max(1, data.total_pages) : 1}
          pagination={pagination}
          onPaginationChange={setPagination}
          getRowId={(r) => r.id}
          onRowClick={(r) => router.push(`/emerging-threats/${r.id}`)}
          emptyMessage={t('emergingThreats.empty.title')}
        />
      )}
    </PageStack>
  )
}

function FilterSelect({
  id,
  label,
  value,
  onChange,
  options,
}: {
  id: string
  label: string
  value: string
  onChange: (v: string) => void
  options: [string, string][]
}) {
  return (
    // Grows to its longest option ("Open (not closed)" was cut off at a fixed w-40).
    <div className="min-w-40 space-y-1">
      <Label htmlFor={id} className="text-xs text-muted-foreground">
        {label}
      </Label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger id={id} className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map(([v, text]) => (
            <SelectItem key={v} value={v}>
              {text}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}
