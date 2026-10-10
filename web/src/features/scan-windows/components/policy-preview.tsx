'use client'

/**
 * Live preview of a draft policy (POST /scan-window-policies/preview,
 * debounced): the assets its selector matches (only those the caller may
 * see) and its next openings. Nothing is stored.
 */

import { AlertCircle } from 'lucide-react'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useDebounce } from '@/hooks/use-debounce'
import { getErrorMessage } from '@/lib/api/error-handler'

import { usePolicyPreview } from '../api/use-scan-windows'
import { formatInZone } from '../lib/schedule'
import type { ScanWindowPolicyRequest } from '../types'

/** Asset names listed before "and N more". */
const LISTED_ASSETS = 8

export function PolicyPreview({ draft }: { draft: ScanWindowPolicyRequest | null }) {
  const { t } = useTranslation()
  const debounced = useDebounce(draft, 500)
  const { data, error, isLoading } = usePolicyPreview(debounced)

  return (
    <section
      aria-labelledby="policy-preview-heading"
      aria-live="polite"
      className="space-y-3 rounded-md border bg-muted/30 p-3"
      data-testid="policy-preview"
    >
      <h3 id="policy-preview-heading" className="text-sm font-semibold">
        {t('scanWindows.preview.title', 'Preview')}
      </h3>
      {!draft ? (
        <p className="text-xs text-muted-foreground">
          {t(
            'scanWindows.preview.fix',
            'Fix the form to see what the policy would select and when it opens.'
          )}
        </p>
      ) : error ? (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            {getErrorMessage(
              error,
              t('scanWindows.preview.failed', 'Could not preview the policy.')
            )}
          </AlertDescription>
        </Alert>
      ) : isLoading && !data ? (
        <Skeleton className="h-20 w-full" />
      ) : data ? (
        <div className="space-y-3 text-sm">
          <div className="space-y-1">
            <p className="text-xs font-medium">{t('scanWindows.preview.targets', 'Targets')}</p>
            {data.asset_dimensions ? (
              <>
                <p data-testid="preview-matched">
                  {t('scanWindows.preview.matched', '{n} matching assets', {
                    n: data.matched_assets ?? 0,
                  })}
                </p>
                {(data.assets?.length ?? 0) > 0 && (
                  <ul className="space-y-0.5 text-xs text-muted-foreground">
                    {data.assets!.slice(0, LISTED_ASSETS).map((a) => (
                      <li key={a.id} className="break-all">
                        {a.name}
                      </li>
                    ))}
                    {(data.matched_assets ?? 0) > LISTED_ASSETS && (
                      <li>
                        {t('scanWindows.waits.more', 'and {n} more', {
                          n:
                            (data.matched_assets ?? 0) -
                            Math.min(LISTED_ASSETS, data.assets!.length),
                        })}
                      </li>
                    )}
                  </ul>
                )}
                {data.truncated && (
                  <p className="text-xs text-muted-foreground" data-testid="preview-truncated">
                    {t(
                      'scanWindows.preview.truncated',
                      'Only assets you can see are counted; the policy applies to every matching asset of the organization.'
                    )}
                  </p>
                )}
              </>
            ) : (
              <p className="text-xs text-muted-foreground">
                {t(
                  'scanWindows.preview.noAssetDims',
                  'Selected by scope entries, zones or programs, or every target: applied to each target when a scan is dispatched.'
                )}
              </p>
            )}
          </div>
          <div className="space-y-1">
            <p className="text-xs font-medium">
              {draft.kind === 'blackout'
                ? t('scanWindows.preview.nextFree', 'Next times scans are allowed')
                : t('scanWindows.preview.nextOpenings', 'Next openings')}
            </p>
            <p className="text-xs">
              {data.open_now
                ? draft.kind === 'blackout'
                  ? t('scanWindows.preview.notActiveNow', 'Not blocking now.')
                  : t('scanWindows.preview.openNow', 'Open now.')
                : draft.kind === 'blackout'
                  ? t('scanWindows.preview.activeNow', 'Blocking now.')
                  : t('scanWindows.preview.closedNow', 'Closed now.')}
            </p>
            {(data.openings?.length ?? 0) === 0 ? (
              <p className="text-xs text-destructive">
                {t('scanWindows.preview.noOpenings', 'No opening in the next 400 days.')}
              </p>
            ) : (
              <ul
                className="space-y-0.5 text-xs text-muted-foreground"
                data-testid="preview-openings"
              >
                {data.openings!.map((o, i) => (
                  <li key={i}>
                    {formatInZone(o.start, draft.timezone)} – {formatInZone(o.end, draft.timezone)}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      ) : null}
    </section>
  )
}
