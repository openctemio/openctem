'use client'

/**
 * Asset attribution section (RFC-036 §6.4): is this asset the organization's,
 * how sure is the platform, and the evidence, one sentence per reason. A
 * person with assets:write confirms, rejects, or marks it as a dependency or
 * monitor-only; scans skip assets that are not confirmed. Used by every
 * asset detail surface (the detail sheet and /assets/{id}).
 */

import { Loader2, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailSection, ErrorState, RelativeTime } from '@/features/shared'
import { usePermissions, Permission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { useAssetAttribution, useDecideAttribution } from '../hooks/use-asset-attribution'
import {
  ATTRIBUTION_STATE_CLASS,
  ATTRIBUTION_STATE_LABEL,
  decisionsFor,
  describeEvidence,
  scanStanding,
  type AttributionDecision,
} from '../lib/attribution'

const DECISION_LABEL: Record<AttributionDecision, string> = {
  confirmed: 'Confirm ours',
  rejected: 'Not ours',
  dependency: 'Dependency',
  monitor_only: 'Monitor only',
  needs_review: 'Back to review',
}

const DECISION_HINT: Record<AttributionDecision, string> = {
  confirmed: 'It is ours: scans may reach it.',
  rejected: 'Not ours: kept out of scans and checks.',
  dependency: "Our name on someone else's infrastructure (CDN, SaaS): passive checks only.",
  monitor_only: 'Watched passively; never scanned.',
  needs_review: 'Undo a decision and let the evidence decide again.',
}

/** Renders one DetailSection; place it inside a <DetailSections>. */
export function AssetAttributionSection({ assetId }: { assetId: string }) {
  const { attribution, isLoading, error, mutate } = useAssetAttribution(assetId)
  const { decide, saving } = useDecideAttribution(assetId)
  const { can } = usePermissions()

  const onDecide = async (state: AttributionDecision) => {
    try {
      const next = await decide(state)
      await mutate(next, { revalidate: false })
      toast.success(`Attribution set to ${ATTRIBUTION_STATE_LABEL[state].toLowerCase()}`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not save the decision')
    }
  }

  return (
    <DetailSection title="Ownership" icon={ShieldCheck}>
      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-5 w-1/3" />
          <Skeleton className="h-5 w-3/4" />
        </div>
      ) : error ? (
        <ErrorState title="ownership" error={error} onRetry={() => mutate()} />
      ) : attribution ? (
        <div className="space-y-3 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <Badge
              variant="outline"
              className={cn('border-transparent', ATTRIBUTION_STATE_CLASS[attribution.state])}
            >
              {ATTRIBUTION_STATE_LABEL[attribution.state]}
            </Badge>
            {attribution.recorded && !attribution.human_decided && (
              <span className="text-muted-foreground tabular-nums">
                {attribution.confidence}% confidence
              </span>
            )}
            {attribution.human_decided && attribution.decided_at && (
              <span className="text-muted-foreground">
                Decided <RelativeTime date={attribution.decided_at} />
              </span>
            )}
            {!attribution.recorded && (
              <span className="text-muted-foreground">
                In the inventory before discovery evidence was kept
              </span>
            )}
          </div>
          <p className="text-muted-foreground">{scanStanding(attribution)}</p>

          {attribution.evidence.length > 0 && (
            <ul className="space-y-1.5" aria-label="Evidence">
              {attribution.evidence.map((e) => (
                <li key={`${e.rule}-${e.source}`} className="flex gap-2">
                  <span className="text-muted-foreground tabular-nums">
                    {Math.round(e.weight * 100)}%
                  </span>
                  <span className="min-w-0 break-words">{describeEvidence(e)}</span>
                </li>
              ))}
            </ul>
          )}

          {can(Permission.AssetsWrite) && (
            <div className="flex flex-wrap gap-2" role="group" aria-label="Decide ownership">
              {[
                ...decisionsFor(attribution.state),
                ...(attribution.human_decided && attribution.state !== 'needs_review'
                  ? (['needs_review'] as AttributionDecision[])
                  : []),
              ].map((d) => (
                <Button
                  key={d}
                  size="sm"
                  variant={d === 'confirmed' ? 'default' : 'outline'}
                  className="h-7"
                  disabled={saving}
                  title={DECISION_HINT[d]}
                  onClick={() => onDecide(d)}
                >
                  {saving && <Loader2 className="me-1 h-3 w-3 animate-spin" />}
                  {DECISION_LABEL[d]}
                </Button>
              ))}
            </div>
          )}
        </div>
      ) : null}
    </DetailSection>
  )
}
