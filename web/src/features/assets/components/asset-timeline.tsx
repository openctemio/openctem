'use client'

/**
 * Asset change timeline (RFC-069 §11): one asset's changes (the asset sheet's
 * Timeline tab and the asset page) and the organization's recent asset
 * changes, newest first and grouped by day, filtered by attribute and
 * source (and tag on the feed). Each entry shows the old and new value, the
 * deciding source and why; "Why this value" opens where the value comes from.
 */

import { useMemo, useState } from 'react'
import { ArrowRight, History, Loader2, Repeat } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, ErrorState, RelativeTime } from '@/features/shared'
import { useAssetChanges } from '../hooks/use-asset-timeline'
import {
  ATTRIBUTE_LABEL,
  RANKABLE_KINDS,
  TRACKED_ATTRIBUTES,
  displayValue,
  type TrackedAttribute,
} from '../lib/attribute-sources'
import { groupByDay, type AssetChange, type ChangeFilters } from '../lib/asset-timeline'

const ALL = 'all'

function useLabels() {
  const { t } = useTranslation()
  return useMemo(
    () => ({
      attribute: (a: string) =>
        t(`assetSources.attribute.${a}`, ATTRIBUTE_LABEL[a as TrackedAttribute] ?? a),
      kind: (k: string) => t(`assetSources.kind.${k}`, k),
      reason: (r: string) => t(`assetTimeline.reason.${r}`, r),
    }),
    [t]
  )
}

function ChangeEntry({
  change,
  showAsset,
  onWhy,
}: {
  change: AssetChange
  showAsset: boolean
  onWhy?: (attribute: string) => void
}) {
  const { t } = useTranslation()
  const l = useLabels()
  const sameValue = change.old_value === change.new_value
  const sourceLabel = change.source.name
    ? `${change.source.name} (${l.kind(change.source.kind)})`
    : l.kind(change.source.kind)
  return (
    <li className="flex flex-col gap-1 py-2 text-sm" data-testid="timeline-entry">
      <div className="flex flex-wrap items-center gap-2">
        <RelativeTime date={change.at} className="text-xs" />
        {showAsset && (
          <Link href={`/assets/${change.asset_id}`} className="font-medium hover:underline">
            {change.asset_name || t('assetTimeline.deletedAsset', 'Deleted asset')}
          </Link>
        )}
        <span className="font-medium">{l.attribute(change.attribute)}</span>
        <Badge variant="secondary" className="font-normal">
          {l.reason(change.reason)}
        </Badge>
        {change.flap_count > 1 && (
          <Badge variant="outline" className="gap-1 font-normal">
            <Repeat className="h-3 w-3" aria-hidden />
            {t('assetTimeline.flapped', 'Changed {count} times within an hour', {
              count: change.flap_count,
            })}
          </Badge>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {sameValue ? (
          <span className="text-muted-foreground">
            {t('assetTimeline.sameValue', '{value} (same value, new deciding source)', {
              value: displayValue(change.new_value),
            })}
          </span>
        ) : (
          <span className="flex items-center gap-1.5">
            <del className="text-muted-foreground">{displayValue(change.old_value)}</del>
            <ArrowRight className="h-3 w-3" aria-label={t('assetTimeline.to', 'changed to')} />
            <ins className="font-medium no-underline">{displayValue(change.new_value)}</ins>
          </span>
        )}
        {(change.added ?? []).map((v) => (
          <Badge key={`+${v}`} variant="outline" className="border-success text-success">
            + {v}
          </Badge>
        ))}
        {(change.removed ?? []).map((v) => (
          <Badge key={`-${v}`} variant="outline" className="border-destructive text-destructive">
            − {v}
          </Badge>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span>
          {t('assetTimeline.decidedBy', 'Decided by {source}', { source: sourceLabel })}
          {change.source.run
            ? ` · ${t('assetTimeline.run', 'run {run}', { run: change.source.run })}`
            : ''}
          {change.actor_id ? ` · ${t('assetTimeline.byPerson', 'by a person')}` : ''}
        </span>
        {onWhy && (
          <button
            type="button"
            className="text-primary hover:underline"
            onClick={() => onWhy(change.attribute)}
          >
            {t('assetTimeline.why', 'Why this value')}
          </button>
        )}
      </div>
    </li>
  )
}

function Filters({
  filters,
  onChange,
  withTag,
}: {
  filters: ChangeFilters
  onChange: (f: ChangeFilters) => void
  withTag: boolean
}) {
  const { t } = useTranslation()
  const l = useLabels()
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Select
        value={filters.attribute || ALL}
        onValueChange={(v) => onChange({ ...filters, attribute: v === ALL ? undefined : v })}
      >
        <SelectTrigger
          className="h-8 w-48"
          aria-label={t('assetTimeline.filterAttribute', 'Attribute')}
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>{t('assetTimeline.allAttributes', 'All attributes')}</SelectItem>
          {TRACKED_ATTRIBUTES.map((a) => (
            <SelectItem key={a} value={a}>
              {l.attribute(a)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select
        value={filters.sourceKind || ALL}
        onValueChange={(v) => onChange({ ...filters, sourceKind: v === ALL ? undefined : v })}
      >
        <SelectTrigger className="h-8 w-44" aria-label={t('assetTimeline.filterSource', 'Source')}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>{t('assetTimeline.allSources', 'All sources')}</SelectItem>
          {(['manual', ...RANKABLE_KINDS] as const).map((k) => (
            <SelectItem key={k} value={k}>
              {k === 'manual' ? t('assetTimeline.person', 'A person') : l.kind(k)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {withTag && (
        <Input
          className="h-8 w-48"
          value={filters.tag ?? ''}
          maxLength={100}
          onChange={(e) => onChange({ ...filters, tag: e.target.value })}
          placeholder={t('assetTimeline.filterTag', 'Asset tag, e.g. bug-bounty')}
          aria-label={t('assetTimeline.filterTagLabel', 'Asset tag')}
        />
      )}
    </div>
  )
}

function TimelineBody({
  assetId,
  filters,
  onWhy,
}: {
  assetId: string | null
  filters: ChangeFilters
  onWhy?: (attribute: string) => void
}) {
  const { t, locale } = useTranslation()
  const { events, error, isLoading, hasMore, loadMore, loadingMore, mutate } = useAssetChanges(
    assetId,
    filters
  )
  const days = useMemo(() => groupByDay(events), [events])

  if (error) {
    return (
      <ErrorState
        title={t('assetTimeline.errorTitle', 'the change timeline')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading && events.length === 0) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    )
  }
  if (events.length === 0) {
    return (
      <EmptyState
        icon={History}
        title={t('assetTimeline.emptyTitle', 'No changes yet')}
        description={t(
          'assetTimeline.empty',
          'A change appears here when a value or the source that decides it changes. Sources reporting the same value again are not listed.'
        )}
      />
    )
  }
  return (
    <div className="space-y-4">
      {days.map((d) => (
        <section key={d.day} aria-label={d.day}>
          <h4 className="text-xs font-semibold uppercase text-muted-foreground">
            {new Date(`${d.day}T00:00:00`).toLocaleDateString(locale, {
              year: 'numeric',
              month: 'short',
              day: 'numeric',
            })}
          </h4>
          <ol className="divide-y">
            {d.events.map((e) => (
              <ChangeEntry key={e.id} change={e} showAsset={!assetId} onWhy={onWhy} />
            ))}
          </ol>
        </section>
      ))}
      {hasMore && (
        <Button variant="outline" size="sm" onClick={() => void loadMore()} disabled={loadingMore}>
          {loadingMore && <Loader2 className="me-1 h-4 w-4 animate-spin" />}
          {t('assetTimeline.loadMore', 'Show older changes')}
        </Button>
      )}
    </div>
  )
}

/** One asset's timeline with its filters. */
export function AssetTimeline({
  assetId,
  onWhy,
}: {
  assetId: string
  onWhy?: (attribute: string) => void
}) {
  const [filters, setFilters] = useState<ChangeFilters>({})
  return (
    <div className="space-y-3">
      <Filters filters={filters} onChange={setFilters} withTag={false} />
      <TimelineBody assetId={assetId} filters={filters} onWhy={onWhy} />
    </div>
  )
}

/** The organization's recent asset changes (assets in the caller's scope). */
export function RecentAssetChanges() {
  const [filters, setFilters] = useState<ChangeFilters>({})
  return (
    <div className="space-y-3">
      <Filters filters={filters} onChange={setFilters} withTag />
      <TimelineBody assetId={null} filters={filters} />
    </div>
  )
}
