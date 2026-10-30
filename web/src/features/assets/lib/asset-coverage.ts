/**
 * Asset coverage (RFC-093): per capability the asset's type needs, what was
 * done, what is due and why something was skipped. Mirrors
 * GET /api/v1/assets/{id}/coverage.
 */
import type { components } from '@/lib/api/generated/api.types'
import type { TranslateVars } from '@/lib/i18n'

export type AssetCoverage =
  components['schemas']['internal_infra_http_handler.AssetCoverageResponse']
export type CoverageEntry = NonNullable<AssetCoverage['entries']>[number]

/**
 * Badge variant per ledger state. A pair that failed on the platform side
 * (the scan did not run) is not the asset failing: it reads as not checked.
 */
export function coverageBadge(
  state: string | undefined,
  gap: boolean | undefined,
  platformSide?: boolean
): 'default' | 'secondary' | 'destructive' | 'outline' {
  if (gap) return 'destructive'
  if (state === 'failed' && platformSide) return 'secondary'
  if (state === 'failed') return 'destructive'
  switch (state) {
    case 'covered':
      return 'default'
    case 'queued':
    case 'due':
      return 'secondary'
    default:
      return 'outline'
  }
}

type Translate = (key: string, fallback?: string, vars?: TranslateVars) => string

/**
 * Why a pair was skipped or paused, translated. A target that did not answer
 * names the organization's own scan zone or sensor that tried, when the API
 * sends it (never a platform sensor).
 */
export function coverageReasonText(
  e: Pick<CoverageEntry, 'reason' | 'unreached_from'>,
  t: Translate
): string {
  const reason = e.reason ?? ''
  if ((reason === 'unreachable' || reason === 'timeout') && e.unreached_from) {
    return t(`assetCoverage.reasonFrom.${reason}`, undefined, { name: e.unreached_from })
  }
  return t(`assetCoverage.reason.${reason}`, reason)
}
