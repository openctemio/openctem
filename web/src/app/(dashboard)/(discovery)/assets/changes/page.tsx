'use client'

import { AssetsSectionTabs } from '@/features/assets/components/assets-section-tabs'
import { useCallback, useMemo, useState } from 'react'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import { RefreshCw, ShieldX } from 'lucide-react'
import { Main } from '@/components/layout'
import {
  PageHeader,
  DataTable,
  EmptyState,
  ErrorState,
  RelativeTime,
  SegmentedLens,
  StackedCell,
} from '@/features/shared'
import { RecentAssetChanges } from '@/features/assets'
import { useTranslation } from '@/context/i18n-provider'
import { safeHref } from '@/lib/safe-href'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { Permission, useHasPermission } from '@/lib/permissions'
import type { StateChangeResponse } from '@/lib/api/generated'
import {
  isChangeView,
  useAssetChangeCounts,
  useAssetChanges,
  type ChangeView,
} from '@/features/asset-changes'

const PAGE_SIZES = [10, 20, 50, 100]

const PERIODS = [
  {
    value: '24h',
    key: 'assetTimeline.activity.period.24h',
    label: 'Last 24 hours',
    ms: 24 * 3600_000,
  },
  { value: '7d', key: 'assetTimeline.activity.period.7d', label: 'Last 7 days', ms: 7 * 86400_000 },
  {
    value: '30d',
    key: 'assetTimeline.activity.period.30d',
    label: 'Last 30 days',
    ms: 30 * 86400_000,
  },
  {
    value: '90d',
    key: 'assetTimeline.activity.period.90d',
    label: 'Last 90 days',
    ms: 90 * 86400_000,
  },
] as const

/** The kinds of activity: the inventory changes, then the value changes (RFC-069). */
type ActivityKind = ChangeView | 'values'

const VIEW_META: Record<ChangeView, { label: string; empty: string; hint: string }> = {
  appeared: {
    label: 'Appeared',
    empty: 'No new assets',
    hint: 'Assets discovered by a scan or added in this period appear here.',
  },
  disappeared: {
    label: 'Disappeared',
    empty: 'No assets disappeared',
    hint: 'Assets no scan has seen within the stale threshold appear here.',
  },
  newly_exposed: {
    label: 'Newly exposed',
    empty: 'Nothing newly exposed',
    hint: 'Assets that became reachable from the internet in this period appear here.',
  },
  exposure_changes: {
    label: 'Exposure changes',
    empty: 'No exposure changes',
    hint: 'Every change to an asset’s exposure level or internet reachability appears here.',
  },
  shadow_it: {
    label: 'Shadow IT',
    empty: 'No shadow IT',
    hint: 'New assets in the shadow scope (found, but not part of any known scope) appear here.',
  },
}

const CHANGE_LABEL: Record<string, string> = {
  appeared: 'Appeared',
  disappeared: 'Disappeared',
  recovered: 'Seen again',
  exposure_changed: 'Exposure',
  internet_exposure_changed: 'Internet reachability',
  renamed: 'Renamed',
  reclassified: 'Reclassified',
}

const SOURCE_LABEL: Record<string, string> = {
  scan: 'Scan',
  manual: 'Manual',
  system: 'System',
  sensor: 'Sensor',
  integration: 'Integration',
  api: 'API',
}

type T = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

function sentence(value: string | undefined): string {
  if (!value) return '—'
  const s = value
    .replace(/_/g, ' ')
    // Acronyms stay upper case: "ip_address" reads "IP address", not "Ip address".
    .replace(/\b(ip|api|dns|iam|vpc|url)\b/gi, (m) => m.toUpperCase())
  return s.charAt(0).toUpperCase() + s.slice(1)
}

/** A field change's value in words: booleans of is_internet_accessible read as reachability. */
function valueLabel(t: T, field: string | undefined, value: string | undefined): string {
  if (field === 'is_internet_accessible') {
    return value === 'true'
      ? t('assetTimeline.activity.internetFacing', 'Internet-facing')
      : t('assetTimeline.activity.notInternetFacing', 'Not internet-facing')
  }
  return sentence(value)
}

function ChangeDetail({ change, t }: { change: StateChangeResponse; t: T }) {
  if (change.field && (change.old_value || change.new_value)) {
    return (
      <span className="inline-flex flex-wrap items-center gap-1.5 text-sm">
        <span className="text-muted-foreground">
          {valueLabel(t, change.field, change.old_value)}
        </span>
        <span className="text-muted-foreground" aria-hidden>
          →
        </span>
        <span className="font-medium">{valueLabel(t, change.field, change.new_value)}</span>
      </span>
    )
  }
  return <span className="text-sm text-muted-foreground">{sentence(change.reason)}</span>
}

function ExposureNow({ change, t }: { change: StateChangeResponse; t: T }) {
  if (!change.asset_exposure) return <span className="text-sm text-muted-foreground">—</span>
  const facing = change.asset_internet_accessible || change.asset_exposure === 'public'
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <span className="text-sm">{sentence(change.asset_exposure)}</span>
      {facing && (
        <Badge variant="outline" className="font-normal">
          {t('assetTimeline.activity.internetFacing', 'Internet-facing')}
        </Badge>
      )}
    </span>
  )
}

export default function AssetChangesPage() {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.AssetsRead)

  const [viewParam, setViewParam] = useUrlFilter('view', 'appeared')
  const [periodParam, setPeriodParam] = useUrlFilter('period', '7d')
  const [internetParam, setInternetParam] = useUrlFilter('internet', 'false')
  const list = useListParams({ pageSizes: PAGE_SIZES, defaultPageSize: 20 })
  const { pagination, setPagination, setPage } = list
  // End of the period window. Set by Refresh so "the last 7 days" is
  // recomputed from now.
  const [anchor, setAnchor] = useState(() => Date.now())

  const kind: ActivityKind =
    viewParam === 'values' ? 'values' : isChangeView(viewParam) ? viewParam : 'appeared'
  const view: ChangeView = kind === 'values' ? 'appeared' : kind
  const isValues = kind === 'values'
  const period = PERIODS.find((p) => p.value === periodParam) ?? PERIODS[1]
  // Newly exposed is internet-facing by definition; the toggle does not apply.
  const internetOnly = internetParam === 'true' && view !== 'newly_exposed'

  // The window ends at `anchor`, rounded to the minute so the request key is
  // stable; Refresh moves it to now.
  const from = useMemo(
    () => new Date(Math.floor(anchor / 60_000) * 60_000 - period.ms).toISOString(),
    [anchor, period.ms]
  )

  const query = useMemo(() => ({ from, internetOnly }), [from, internetOnly])
  // The value feed has its own request; the inventory list is not asked for then.
  const { changes, total, error, isLoading, mutate } = useAssetChanges(
    view,
    query,
    pagination,
    canRead && !isValues
  )
  // Counts follow the internet-facing toggle too, so a number and the list it
  // opens always agree (the hook leaves it off for newly exposed, like the list).
  const countQuery = useMemo(
    () => ({ from, internetOnly: internetParam === 'true' }),
    [from, internetParam]
  )
  const { counts, mutate: mutateCounts } = useAssetChangeCounts(countQuery, canRead)

  const selectKind = useCallback(
    (next: ActivityKind) => {
      setViewParam(next)
      setPage(1)
    },
    [setViewParam, setPage]
  )

  const kindOptions = [
    ...(Object.keys(VIEW_META) as ChangeView[]).map((key) => ({
      value: key as ActivityKind,
      label: t(`assetTimeline.activity.kind.${key}`, VIEW_META[key].label),
      count: counts?.[key],
    })),
    {
      value: 'values' as ActivityKind,
      label: t('assetTimeline.activity.kind.values', 'Values'),
      description: t(
        'assetTimeline.activity.kind.valuesHint',
        'Changes of an asset value or of the source that decides it'
      ),
    },
  ]

  const columns = useMemo<ColumnDef<StateChangeResponse>[]>(
    () => [
      {
        id: 'asset',
        header: t('assetTimeline.activity.col.asset', 'Asset'),
        enableSorting: false,
        cell: ({ row }) => {
          const c = row.original
          const name = c.asset_name || t('assetTimeline.deletedAsset', 'Deleted asset')
          return (
            <StackedCell
              truncate
              className="max-w-[320px]"
              primary={
                c.asset_name && c.asset_id ? (
                  <Link
                    href={safeHref(`/assets/${encodeURIComponent(c.asset_id)}`) ?? '/assets'}
                    className="hover:underline"
                  >
                    {name}
                  </Link>
                ) : (
                  <span className="text-muted-foreground">{name}</span>
                )
              }
              secondary={sentence(c.asset_type)}
            />
          )
        },
      },
      {
        id: 'change',
        header: t('assetTimeline.activity.col.change', 'Change'),
        enableSorting: false,
        cell: ({ row }) => {
          const type = row.original.change_type ?? ''
          return (
            <Badge variant="secondary" className="font-normal">
              {CHANGE_LABEL[type]
                ? t(`assetTimeline.activity.change.${type}`, CHANGE_LABEL[type])
                : sentence(type)}
            </Badge>
          )
        },
      },
      {
        id: 'detail',
        header: t('assetTimeline.activity.col.detail', 'Detail'),
        enableSorting: false,
        cell: ({ row }) => <ChangeDetail change={row.original} t={t} />,
      },
      {
        id: 'exposure',
        header: t('assetTimeline.activity.col.exposure', 'Exposure now'),
        enableSorting: false,
        cell: ({ row }) => <ExposureNow change={row.original} t={t} />,
      },
      {
        id: 'source',
        header: t('assetTimeline.activity.col.source', 'Source'),
        enableSorting: false,
        cell: ({ row }) => {
          const src = row.original.source ?? ''
          return (
            <span className="text-sm">
              {SOURCE_LABEL[src]
                ? t(`assetTimeline.activity.source.${src}`, SOURCE_LABEL[src])
                : sentence(src)}
            </span>
          )
        },
      },
      {
        id: 'changed_at',
        header: t('assetTimeline.activity.col.when', 'When'),
        enableSorting: false,
        cell: ({ row }) => <RelativeTime date={row.original.changed_at} />,
      },
    ],
    [t]
  )

  const title = t('assetTimeline.activity.title', 'Activity')
  const description = t(
    'assetTimeline.activity.description',
    'What changed on your assets: new, gone and newly exposed assets over a period, and every change of an asset value.'
  )

  if (!canRead) {
    return (
      <Main>
        <PageHeader title={title} description={description} />
        <EmptyState
          className="mt-5"
          icon={ShieldX}
          title={t('assetTimeline.noAccessTitle', 'Access denied')}
          description={t(
            'assetTimeline.noAccess',
            'You do not have permission to view assets. Ask your administrator for access.'
          )}
        />
      </Main>
    )
  }

  const refresh = () => {
    setAnchor(Date.now())
    void mutate()
    void mutateCounts()
  }

  const toolbarStart =
    view === 'newly_exposed' ? undefined : (
      <div className="flex items-center gap-2">
        <Switch
          id="internet-only"
          checked={internetParam === 'true'}
          onCheckedChange={(checked) => {
            setInternetParam(checked ? 'true' : 'false')
            setPage(1)
          }}
        />
        <Label htmlFor="internet-only" className="cursor-pointer text-sm font-normal">
          {t('assetTimeline.activity.internetOnly', 'Internet-facing only')}
        </Label>
      </div>
    )

  const refreshLabel = t('assetTimeline.activity.refresh', 'Refresh')
  const toolbarEnd = (
    <Button variant="outline" size="sm" className="h-9" onClick={refresh} aria-label={refreshLabel}>
      <RefreshCw className="h-4 w-4" />
    </Button>
  )

  const meta = isValues ? undefined : VIEW_META[view]
  const periodLabel = t(period.key, period.label)

  return (
    <Main>
      <PageHeader title={title} description={description}>
        {!isValues && (
          <Select
            value={period.value}
            onValueChange={(value) => {
              setPeriodParam(value)
              setPage(1)
            }}
          >
            <SelectTrigger
              className="h-9 w-[150px]"
              aria-label={t('assetTimeline.activity.period.label', 'Period')}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PERIODS.map((p) => (
                <SelectItem key={p.value} value={p.value}>
                  {t(p.key, p.label)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </PageHeader>
      <AssetsSectionTabs />

      {/* The kinds of activity, with their counts in the period (research/242 D2). */}
      <div className="mt-5 -mx-1 overflow-x-auto px-1 pb-1">
        <SegmentedLens
          label={t('assetTimeline.activity.kind.label', 'Kind of change')}
          value={kind}
          options={kindOptions}
          onChange={selectKind}
          countNoun={t('assetTimeline.activity.countNoun', 'changes')}
        />
      </div>

      <div className="mt-4">
        {isValues ? (
          <RecentAssetChanges />
        ) : error && !isLoading ? (
          <ErrorState title="changes" error={error} onRetry={() => mutate()} />
        ) : isLoading && changes.length === 0 ? (
          <div className="space-y-2">
            <Skeleton className="h-9 w-full max-w-sm" />
            {Array.from({ length: 8 }).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : (
          <DataTable
            columns={columns}
            data={changes}
            getRowId={(c) => c.id ?? `${c.asset_id}-${c.changed_at}`}
            showSearch={false}
            showColumnToggle={false}
            toolbarStart={toolbarStart}
            toolbarEnd={toolbarEnd}
            manualPagination
            rowCount={total}
            pagination={pagination}
            onPaginationChange={setPagination}
            pageSizeOptions={PAGE_SIZES}
            emptyMessage={t('assetTimeline.activity.emptyIn', '{empty} in the {period}', {
              empty: t(`assetTimeline.activity.empty.${view}`, meta?.empty ?? ''),
              period: periodLabel.toLowerCase(),
            })}
            emptyDescription={
              internetOnly
                ? t(
                    'assetTimeline.activity.internetOnlyHint',
                    'Turn off “Internet-facing only” to include internal assets.'
                  )
                : t(`assetTimeline.activity.hint.${view}`, meta?.hint ?? '')
            }
          />
        )}
      </div>
    </Main>
  )
}
