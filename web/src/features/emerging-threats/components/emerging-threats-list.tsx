'use client'

/**
 * The emerging-threat list: summary strip, filters, and a server-paged table
 * of alerts ranked by exploitation-weighted score. Server text (titles) is
 * rendered as plain text.
 */

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { Siren } from 'lucide-react'
import Link from '@/components/link'
import { Input } from '@/components/ui/input'
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
import { MetricStrip, type MetricStripItem } from '@/features/shared/components/metric-strip'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { DEFAULT_PER_PAGE, useEmergingThreats } from '../api'
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

const ALL = 'all'

export function EmergingThreatsList() {
  const { t } = useTranslation()
  const router = useRouter()
  const dateLocale = useDateLocale()
  const eventLabel = useEventKindLabel()
  const [level, setLevel] = useState<AlertLevel | typeof ALL>(ALL)
  const [state, setState] = useState<StateFilter>('open')
  const [tier, setTier] = useState<AlertTier | typeof ALL>(ALL)
  const [internetOnly, setInternetOnly] = useState(false)
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: DEFAULT_PER_PAGE })

  useEffect(() => {
    const id = setTimeout(() => setSearch(searchInput), 300)
    return () => clearTimeout(id)
  }, [searchInput])

  const { data, error, isLoading, mutate } = useEmergingThreats({
    level: level === ALL ? undefined : level,
    state,
    tier: tier === ALL ? undefined : tier,
    internetOnly,
    search,
    page: pagination.pageIndex + 1,
    perPage: pagination.pageSize,
  })

  // Any filter change goes back to the first page.
  const resetPage = () => setPagination((p) => ({ ...p, pageIndex: 0 }))

  const rows = useMemo(() => data?.data ?? [], [data])
  const summary = data?.summary

  const strip: MetricStripItem[] = [
    { key: 'open', label: t('emergingThreats.summary.open'), value: summary?.open ?? 0 },
    {
      key: 'immediate',
      label: t('emergingThreats.summary.immediate'),
      value: summary?.immediate ?? 0,
      tone: 'danger',
      active: level === 'immediate',
      onClick: () => {
        setLevel((l) => (l === 'immediate' ? ALL : 'immediate'))
        resetPage()
      },
    },
    { key: 'digest', label: t('emergingThreats.summary.digest'), value: summary?.digest ?? 0 },
    { key: 'listed', label: t('emergingThreats.summary.listed'), value: summary?.listed ?? 0 },
    {
      key: 'kev',
      label: t('emergingThreats.summary.kev'),
      value: summary?.kev ?? 0,
      tone: 'danger',
    },
    {
      key: 'internet',
      label: t('emergingThreats.summary.internetFacing'),
      value: summary?.internet_facing ?? 0,
      tone: 'warning',
      active: internetOnly,
      onClick: () => {
        setInternetOnly((v) => !v)
        resetPage()
      },
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
            <RelativeTime date={row.original.event_at} locale={dateLocale} />
          </div>
        ),
      },
    ],
    [t, eventLabel, dateLocale]
  )

  return (
    <div className="mt-4 space-y-4">
      <MetricStrip items={strip} loading={isLoading && !data} />

      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-48 flex-1 space-y-1">
          <Label htmlFor="et-search" className="text-xs text-muted-foreground">
            {t('emergingThreats.filter.search')}
          </Label>
          <Input
            id="et-search"
            value={searchInput}
            placeholder={t('emergingThreats.filter.searchPlaceholder')}
            onChange={(e) => {
              setSearchInput(e.target.value)
              resetPage()
            }}
          />
        </div>
        <FilterSelect
          id="et-level"
          label={t('emergingThreats.filter.level')}
          value={level}
          onChange={(v) => {
            setLevel(v as AlertLevel | typeof ALL)
            resetPage()
          }}
          options={[
            [ALL, t('emergingThreats.filter.allLevels')],
            ...LEVELS.map((l): [string, string] => [l, t(`emergingThreats.level.${l}`)]),
          ]}
        />
        <FilterSelect
          id="et-state"
          label={t('emergingThreats.filter.state')}
          value={state}
          onChange={(v) => {
            setState(v as StateFilter)
            resetPage()
          }}
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
          onChange={(v) => {
            setTier(v as AlertTier | typeof ALL)
            resetPage()
          }}
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
            onCheckedChange={(v) => {
              setInternetOnly(v)
              resetPage()
            }}
          />
          <Label htmlFor="et-internet" className="text-sm">
            {t('emergingThreats.filter.internetOnly')}
          </Label>
        </div>
      </div>

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
    </div>
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
    <div className="w-40 space-y-1">
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
