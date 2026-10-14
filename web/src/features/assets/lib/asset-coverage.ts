/**
 * Asset coverage (RFC-093): per capability the asset's type needs, what was
 * done, what is due and why something was skipped. Mirrors
 * GET /api/v1/assets/{id}/coverage.
 */
import type { components } from '@/lib/api/generated/api.types'

export type AssetCoverage =
  components['schemas']['internal_infra_http_handler.AssetCoverageResponse']
export type CoverageEntry = NonNullable<AssetCoverage['entries']>[number]

/** Badge variant per ledger state. */
export function coverageBadge(
  state: string | undefined,
  gap: boolean | undefined
): 'default' | 'secondary' | 'destructive' | 'outline' {
  if (gap || state === 'failed') return 'destructive'
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
