'use client'

/**
 * How current an asset's data is (RFC-075): per enrichable attribute class
 * (DNS, registration, network owner, HTTP, TLS, ports) when it was last
 * observed and by which tool, its freshness window, and its state; plus the
 * asset's automatic enrichment. Used by the detail sheet and /assets/{id}.
 */

import { Activity } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection, ErrorState, RelativeTime } from '@/features/shared'
import { useAssetFreshness } from '../hooks/use-asset-freshness'
import { FRESHNESS_BADGE, enrichmentStatus, ttlParts } from '../lib/asset-freshness'

export function AssetFreshnessSection({ assetId }: { assetId: string }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useAssetFreshness(assetId)

  const title = t('assetFreshness.title', 'Data freshness')
  if (isLoading) {
    return (
      <DetailSection title={title} icon={Activity}>
        <Skeleton className="h-16 w-full" />
      </DetailSection>
    )
  }
  if (error) {
    return (
      <DetailSection title={title} icon={Activity}>
        <ErrorState
          title={t('assetFreshness.errorTitle', 'data freshness')}
          error={error}
          onRetry={() => mutate()}
        />
      </DetailSection>
    )
  }
  if (!data) return null

  const stateLabel = (s: string) => t(`assetFreshness.state.${s}`, s)
  const enrichment = data.enrichment

  return (
    <DetailSection
      title={title}
      icon={Activity}
      actions={<Badge variant={FRESHNESS_BADGE[data.state]}>{stateLabel(data.state)}</Badge>}
    >
      {data.classes.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {t(
            'assetFreshness.noClasses',
            'Nothing about this kind of asset is enriched automatically.'
          )}
        </p>
      ) : (
        <ul className="divide-y text-sm" aria-label={title}>
          {data.classes.map((c) => {
            const ttl = ttlParts(c.ttl_seconds)
            return (
              <li key={c.class} className="flex flex-wrap items-center justify-between gap-2 py-2">
                <div className="min-w-0">
                  <div className="font-medium">{t(`assetFreshness.class.${c.class}`, c.class)}</div>
                  <div className="text-xs text-muted-foreground">
                    {c.observed_at ? (
                      <>
                        {t('assetFreshness.observedBy', 'Seen by {source}', {
                          source: c.source || '—',
                        })}{' '}
                        <RelativeTime date={c.observed_at} className="text-xs" />
                      </>
                    ) : (
                      t('assetFreshness.neverObserved', 'Not observed yet')
                    )}
                    {', '}
                    {t(`assetFreshness.ttl.${ttl.key}`, `fresh for ${ttl.n}`, { n: ttl.n })}
                  </div>
                </div>
                <Badge variant={FRESHNESS_BADGE[c.state]}>{stateLabel(c.state)}</Badge>
              </li>
            )
          })}
        </ul>
      )}
      {data.resolution && (
        <p className="mt-2 text-xs text-muted-foreground" data-testid="asset-resolution-status">
          {data.resolution.state === 'not_resolving'
            ? t('assetFreshness.resolution.not_resolving', 'DNS has no answer for this name')
            : t('assetFreshness.resolution.resolving', 'This name resolves')}
          {', '}
          {data.resolution.resolved_at ? (
            <>
              {t('assetFreshness.resolution.lastResolved', 'last resolved')}{' '}
              <RelativeTime date={data.resolution.resolved_at} className="text-xs" />
            </>
          ) : (
            t('assetFreshness.resolution.neverResolved', 'never seen resolving')
          )}
        </p>
      )}
      {enrichment && (
        <p className="mt-2 text-xs text-muted-foreground" data-testid="asset-enrichment-status">
          {t(
            `assetFreshness.enrichment.${enrichmentStatus(enrichment)}`,
            enrichmentStatus(enrichment)
          )}{' '}
          <RelativeTime
            date={enrichment.dispatched_at ?? enrichment.requested_at}
            className="text-xs"
          />
          {enrichment.last_run_id && (
            <>
              {', '}
              <Link
                href={`/scans/runs?run=${encodeURIComponent(enrichment.last_run_id)}`}
                className="underline"
              >
                {t('assetFreshness.viewRun', 'View run')}
              </Link>
            </>
          )}
        </p>
      )}
    </DetailSection>
  )
}
