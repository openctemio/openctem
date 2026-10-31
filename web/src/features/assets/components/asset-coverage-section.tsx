'use client'

/**
 * What each capability an asset needs has done (RFC-093): per capability its
 * state, why it was skipped, when it last ran and succeeded, and whether it
 * is a coverage gap. Used by the detail sheet and /assets/{id}.
 */

import { useSettleSignal } from '@/features/shared/components/settle-group'
import { ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection, ErrorState, RelativeTime } from '@/features/shared'
import { useAssetCoverage } from '../hooks/use-asset-coverage'
import { coverageBadge, coverageReasonText } from '../lib/asset-coverage'

export function AssetCoverageSection({ assetId }: { assetId: string }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useAssetCoverage(assetId)
  useSettleSignal(isLoading)

  const title = t('assetCoverage.title', 'Coverage')
  if (isLoading) {
    return (
      <DetailSection title={title} icon={ShieldCheck}>
        <Skeleton className="h-16 w-full" />
      </DetailSection>
    )
  }
  if (error) {
    return (
      <DetailSection title={title} icon={ShieldCheck}>
        <ErrorState
          title={t('assetCoverage.errorTitle', 'coverage')}
          error={error}
          onRetry={() => mutate()}
        />
      </DetailSection>
    )
  }
  if (!data) return null
  const entries = data.entries ?? []
  const gaps = data.gaps ?? 0

  return (
    <DetailSection
      title={title}
      icon={ShieldCheck}
      actions={
        gaps > 0 ? (
          <Badge variant="destructive">{t('assetCoverage.gaps', '{n} gaps', { n: gaps })}</Badge>
        ) : undefined
      }
    >
      {entries.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {t('assetCoverage.none', 'Nothing is scanned automatically for this kind of asset.')}
        </p>
      ) : (
        <ul className="divide-y text-sm" aria-label={title}>
          {entries.map((e) => (
            <li
              key={`${e.capability}/${e.vantage ?? ''}`}
              className="flex flex-wrap items-center justify-between gap-2 py-2"
            >
              <div className="min-w-0">
                <div className="font-medium">
                  {t(`assetCoverage.capability.${e.capability}`, e.capability ?? '')}
                </div>
                <div className="text-xs text-muted-foreground">
                  {e.last_success_at ? (
                    <>
                      {t('assetCoverage.lastSuccess', 'Last done')}{' '}
                      <RelativeTime date={e.last_success_at} className="text-xs" />
                    </>
                  ) : (
                    t('assetCoverage.neverDone', 'Never done')
                  )}
                  {e.last_outcome === 'no_output' &&
                    `, ${t('assetCoverage.noOutput', 'found nothing')}`}
                  {e.last_outcome === 'no_answer' &&
                    `, ${t('assetCoverage.noAnswer', 'the name has no DNS answer; checked again later')}`}
                  {e.platform_side &&
                    `, ${t('assetCoverage.platformSide', 'the scan could not run on the scanner side, so this says nothing about the asset; tried again later')}`}
                  {e.reason && `, ${coverageReasonText(e, t)}`}
                  {e.next_due_at && e.state !== 'not_applicable' && (
                    <>
                      {', '}
                      {t('assetCoverage.nextDue', 'next')}{' '}
                      <RelativeTime date={e.next_due_at} className="text-xs" />
                    </>
                  )}
                </div>
                {e.last_error && (
                  <div
                    className={`truncate text-xs ${e.platform_side ? 'text-muted-foreground' : 'text-destructive'}`}
                    title={e.last_error}
                  >
                    {e.last_error}
                  </div>
                )}
              </div>
              <Badge variant={coverageBadge(e.state, e.gap, e.platform_side)}>
                {e.gap
                  ? t('assetCoverage.gap', 'Gap')
                  : e.state === 'failed' && e.platform_side
                    ? t('assetCoverage.state.not_checked', 'Not checked')
                    : t(`assetCoverage.state.${e.state}`, e.state ?? '')}
              </Badge>
            </li>
          ))}
        </ul>
      )}
    </DetailSection>
  )
}
