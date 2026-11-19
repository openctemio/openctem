'use client'

import { getAssetTypeLabel } from '@/features/assets/lib/asset-type-icon'
import { AssetsSectionTabs } from '@/features/assets/components/assets-section-tabs'
import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Globe, History, RefreshCw } from 'lucide-react'
import { Main } from '@/components/layout'
import {
  PageHeader,
  DataTable,
  EmptyState,
  ErrorState,
  RelativeTime,
  FilterSelect,
  PageStack,
} from '@/features/shared'
import { ListCount, ListTitleRow } from '@/features/shared/components/list-title-row'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { RowNameLink } from '@/features/shared/components/row-name-link'
import { assetDetailHref } from '@/features/findings/lib/asset-link'
import { accessStateOf } from '@/lib/api/access-state'
import { RecentAssetChanges } from '@/features/assets'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { GatedButton } from '@/features/shared/components/gated-button'
import { useRouter } from 'next/navigation'
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
type PeriodValue = (typeof PERIODS)[number]['value']

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
      <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-sm">
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
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
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
  const router = useRouter()
  const canRead = useHasPermission(Permission.AssetsRead)

  const [viewParam, setViewParam] = useUrlFilter('view', 'appeared')
  const [periodParam, setPeriodParam] = useUrlFilter('period', '7d')
  const [internetParam, setInternetParam] = useUrlFilter('internet', 'false')
  const list = useListParams()
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
        meta: {
          kind: 'asset',
          pin: 'start',
          label: t('assetTimeline.activity.col.asset', 'Asset'),
        },
        header: t('assetTimeline.activity.col.asset', 'Asset'),
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => {
          const c = row.original
          const name = c.asset_name || t('assetTimeline.deletedAsset', 'Deleted asset')
          // One line: the name (a link while the asset exists), then its type.
          // No width of its own (w-0): a long name never widens the table past
          // its frame; it ends in an ellipsis inside the column.
          return (
            <span className="flex w-0 min-w-full items-baseline gap-2">
              {c.asset_name && c.asset_id ? (
                <RowNameLink
                  href={assetDetailHref(c.asset_id)}
                  onOpen={() => router.push(assetDetailHref(c.asset_id!))}
                  title={name}
                >
                  {name}
                </RowNameLink>
              ) : (
                <span className="truncate text-muted-foreground">{name}</span>
              )}
              <span className="shrink-0 text-xs text-muted-foreground">
                {c.asset_type ? getAssetTypeLabel(c.asset_type, t) : sentence(c.asset_type)}
              </span>
            </span>
          )
        },
      },
      {
        id: 'change',
        meta: {
          kind: 'status',
          width: 176,
          label: t('assetTimeline.activity.col.change', 'Change'),
        },
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
        meta: {
          kind: 'text',
          // Asset 200 + Change 176 + this + When 144 fit a 1024 screen (frame 700).
          minWidth: 180,
          maxWidth: 360,
          label: t('assetTimeline.activity.col.detail', 'Detail'),
        },
        header: t('assetTimeline.activity.col.detail', 'Detail'),
        enableSorting: false,
        cell: ({ row }) => <ChangeDetail change={row.original} t={t} />,
      },
      {
        id: 'exposure',
        meta: {
          kind: 'text',
          width: 208,
          // Dropped first: the frame of a 1280 screen (956) holds the rest.
          hideBelow: 1100,
          label: t('assetTimeline.activity.col.exposure', 'Exposure now'),
        },
        header: t('assetTimeline.activity.col.exposure', 'Exposure now'),
        enableSorting: false,
        cell: ({ row }) => <ExposureNow change={row.original} t={t} />,
      },
      {
        id: 'source',
        meta: {
          kind: 'text',
          width: 112,
          // A 1024 screen (frame 700) keeps Asset, Change, Detail and When.
          hideBelow: 900,
          label: t('assetTimeline.activity.col.source', 'Source'),
        },
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
        meta: {
          kind: 'datetime-recent',
          // "khoảng 2 giờ trước" whole: the kind's 104 cuts the Vietnamese words.
          width: 144,
          label: t('assetTimeline.activity.col.when', 'When'),
        },
        header: t('assetTimeline.activity.col.when', 'When'),
        enableSorting: false,
        cell: ({ row }) => <RelativeTime date={row.original.changed_at} />,
      },
    ],
    [t, router]
  )

  const title = t('assetTimeline.activity.title', 'Activity')
  const description = t(
    'assetTimeline.activity.description',
    'What changed on your assets: new, gone and newly exposed assets over a period, and every change of an asset value.'
  )

  if (!canRead) {
    return (
      <Main>
        <PageStack>
          <PageHeader title={title} description={description} />
          <NoAccessState
            title={t('assetTimeline.activity.subject', 'asset activity')}
            permission={Permission.AssetsRead}
          />
        </PageStack>
      </Main>
    )
  }

  const refresh = () => {
    setAnchor(Date.now())
    void mutate()
    void mutateCounts()
  }

  // The kind of change is a filter token, first in the toolbar, not a second
  // row under the tabs (research/249 R21). One kind is always chosen: the
  // kinds are different lists (Values is the value-change feed).
  const kindSelect = (
    <FilterSelect<ActivityKind>
      label={t('assetTimeline.activity.kind.short', 'Kind')}
      value={kind}
      clearable={false}
      foldLabel
      options={kindOptions}
      onChange={(next) => selectKind((next || 'appeared') as ActivityKind)}
    />
  )
  const periodSelect = (
    <FilterSelect<PeriodValue>
      label={t('assetTimeline.activity.period.label', 'Period')}
      value={period.value}
      clearable={false}
      foldLabel
      options={PERIODS.map((p) => ({ value: p.value, label: t(p.key, p.label) }))}
      onChange={(value) => {
        setPeriodParam(value || '7d')
        setPage(1)
      }}
    />
  )
  // Newly exposed is internet-facing by definition: the toggle stays in its
  // place, pressed and locked, so choosing a kind moves nothing in the toolbar.
  const internetLocked = view === 'newly_exposed'
  const internetOn = internetLocked || internetParam === 'true'
  const toolbarStart = (
    <>
      {kindSelect}
      {periodSelect}
      {/* A filter token at the toolbar's control height, pressed while on. */}
      <GatedButton
        allowed={!internetLocked}
        reason={t(
          'assetTimeline.activity.internetLocked',
          'Newly exposed assets are always internet-facing'
        )}
        size="sm"
        variant={internetOn ? 'secondary' : 'outline'}
        aria-pressed={internetOn}
        aria-label={t('assetTimeline.activity.internetOnly', 'Internet-facing only')}
        data-slot="internet-only-toggle"
        className="shrink-0"
        onClick={() => {
          setInternetParam(internetOn ? 'false' : 'true')
          setPage(1)
        }}
      >
        <Globe className="size-4" aria-hidden />
        <span className="max-md:hidden">
          {t('assetTimeline.activity.internetOnly', 'Internet-facing only')}
        </span>
        <span className="md:hidden">
          {t('assetTimeline.activity.internetShort', 'Internet-facing')}
        </span>
      </GatedButton>
    </>
  )

  const refreshLabel = t('assetTimeline.activity.refresh', 'Refresh')
  const refreshButton = (
    <Button variant="outline" size="icon" onClick={refresh} aria-label={refreshLabel}>
      <RefreshCw className="h-4 w-4" aria-hidden />
    </Button>
  )
  const kindTitle = isValues
    ? t('assetTimeline.activity.kind.values', 'Values')
    : t(`assetTimeline.activity.kind.${view}`, VIEW_META[view].label)
  const noAccess = !!error && accessStateOf(error) === 'no_access'

  const meta = isValues ? undefined : VIEW_META[view]
  const periodLabel = t(period.key, period.label)

  return (
    <Main>
      <PageStack>
        <PageHeader title={title} description={description} />
        <AssetsSectionTabs />

        {/* The list's title row: the kind on screen and its one count (the
            changes of that kind in the period), then Refresh. The value feed
            counts nothing, so it has no count. */}
        <ListTitleRow
          title={kindTitle}
          count={
            isValues ? undefined : (
              <ListCount
                total={total}
                loading={(isLoading && changes.length === 0) || !!error}
                label={t(
                  'assetTimeline.activity.count',
                  '{count, plural, one {# change} other {# changes}}',
                  { count: total }
                )}
              />
            )
          }
        >
          {!isValues && refreshButton}
        </ListTitleRow>

        {isValues ? (
          <RecentAssetChanges leading={kindSelect} />
        ) : noAccess ? (
          <NoAccessState
            title={t('assetTimeline.activity.subject', 'asset activity')}
            permission={Permission.AssetsRead}
          />
        ) : (
          // The toolbar (kind, period) stays while the list loads or fails.
          <DataTable
            columns={columns}
            data={changes}
            caption={t('assetTimeline.activity.caption', 'Asset activity: {kind}', {
              kind: kindTitle,
            })}
            isLoading={isLoading && changes.length === 0}
            errorState={
              error && !isLoading ? (
                <ErrorState
                  title={t('assetTimeline.activity.errorTitle', 'changes')}
                  error={error}
                  onRetry={() => mutate()}
                />
              ) : undefined
            }
            getRowId={(c) => c.id ?? `${c.asset_id}-${c.changed_at}`}
            showSearch={false}
            toolbarStart={toolbarStart}
            manualPagination
            rowCount={total}
            pagination={pagination}
            onPaginationChange={setPagination}
            paginationNoun={t('assetTimeline.activity.noun', 'changes')}
            // Nothing happened in the period: the list is narrowed only by the
            // period and the internet-facing switch, so there is no first run.
            emptyState={
              <EmptyState
                icon={History}
                title={t('assetTimeline.activity.emptyIn', '{empty} in the {period}', {
                  empty: t(`assetTimeline.activity.empty.${view}`, meta?.empty ?? ''),
                  period: periodLabel.toLowerCase(),
                })}
                description={
                  internetOnly
                    ? t(
                        'assetTimeline.activity.internetOnlyHint',
                        'Turn off “Internet-facing only” to include internal assets.'
                      )
                    : t(`assetTimeline.activity.hint.${view}`, meta?.hint ?? '')
                }
              />
            }
          />
        )}
      </PageStack>
    </Main>
  )
}
