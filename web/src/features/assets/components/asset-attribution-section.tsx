'use client'

/**
 * Asset ownership and scope (RFC-036 §6.4, RFC-054 §4.2/§6.6): is this asset
 * the organization's, how sure is the platform and why, and, separately, may
 * scans reach it. Confirming ownership is bookkeeping; only a scope entry
 * lets scans reach a name, so the card shows both answers side by side and
 * says so in words. Each ownership decision is a labelled choice with its
 * consequence written next to it (not only in a tooltip). Used by every asset
 * detail surface (the detail sheet and /assets/{id}).
 */

import { useState } from 'react'
import { Info, Loader2, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailSection, ErrorState, RelativeTime } from '@/features/shared'
import {
  ScopeEntryDialog,
  type ScopeEntryDraft,
} from '@/features/scope/components/scope-entry-dialog'
import { usePermissions, Permission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { useAssetAttribution, useDecideAttribution } from '../hooks/use-asset-attribution'
import {
  ATTRIBUTION_STATE_CLASS,
  ATTRIBUTION_STATE_LABEL,
  decisionsFor,
  describeEvidence,
  scanStanding,
  scopeStandingText,
  type AttributionDecision,
} from '../lib/attribution'

/** Button labels: what the person is saying about the asset. */
export const DECISION_LABEL: Record<AttributionDecision, string> = {
  confirmed: 'Ours',
  rejected: 'Not ours',
  dependency: 'Ours, on third-party infrastructure',
  monitor_only: 'Watch only',
  needs_review: 'Undo the decision',
}

/** What each decision does, shown next to its button. */
export const DECISION_HINT: Record<AttributionDecision, string> = {
  confirmed:
    'It belongs to your organization and stays in the inventory. Scans still need a scope entry that covers it.',
  rejected:
    'It is not yours. It leaves the inventory, and scans never touch it or the names below it.',
  dependency:
    'Your name on someone else’s servers (CDN, SaaS, hosting). Only passive and takeover checks run.',
  monitor_only: 'Keep watching it passively (certificates, DNS). It is never actively scanned.',
  needs_review: 'Clear the decision and let the evidence decide again.',
}

/** Renders one DetailSection; place it inside a <DetailSections>. */
export function AssetAttributionSection({
  assetId,
  assetName,
  assetType,
}: {
  assetId: string
  /** For "Add to scope" (prefills the entry). */
  assetName?: string
  assetType?: string
}) {
  const { attribution, isLoading, error, mutate } = useAssetAttribution(assetId)
  const { decide, saving } = useDecideAttribution(assetId)
  const { can } = usePermissions()
  const [draft, setDraft] = useState<ScopeEntryDraft | null>(null)

  const onDecide = async (state: AttributionDecision) => {
    try {
      const next = await decide(state)
      await mutate(next, { revalidate: false })
      toast.success(`Ownership set to ${ATTRIBUTION_STATE_LABEL[state].toLowerCase()}`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not save the decision')
    }
  }

  const scope = attribution ? scopeStandingText(attribution) : null
  const canAddScope = can(Permission.ScopeWrite) && !!assetName

  return (
    <DetailSection title="Ownership and scope" icon={ShieldCheck}>
      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-5 w-1/3" />
          <Skeleton className="h-5 w-3/4" />
        </div>
      ) : error ? (
        <ErrorState title="ownership" error={error} onRetry={() => mutate()} />
      ) : attribution ? (
        <div className="space-y-4 text-sm">
          <dl className="grid grid-cols-[6.5rem_1fr] gap-x-3 gap-y-2">
            <dt className="text-muted-foreground">Ours?</dt>
            <dd className="flex min-w-0 flex-wrap items-center gap-2">
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
            </dd>
            <dt className="text-muted-foreground">Scans</dt>
            <dd className="min-w-0 space-y-1">
              {scope && <p className={cn(scope.ok ? 'text-foreground' : '')}>{scope.text}</p>}
              {/* The ownership side of the answer; the scope line above already
                  says "no entry covers it" when that is the reason. */}
              {!(
                scope &&
                ['unattributed', 'out_of_scope'].includes(
                  attribution.active_checks_blocked_by ?? ''
                )
              ) && <p className="text-muted-foreground">{scanStanding(attribution)}</p>}
              {scope && !scope.ok && scope.canAdd && canAddScope && (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7"
                  onClick={() =>
                    setDraft({
                      pattern: assetName,
                      target_type: assetType === 'ip_address' ? 'ip_address' : undefined,
                    })
                  }
                >
                  Add to scope
                </Button>
              )}
            </dd>
          </dl>

          <p className="flex gap-2 rounded-md bg-muted/50 px-3 py-2 text-xs text-muted-foreground">
            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
            Saying an asset is yours records ownership. It does not authorize scanning: a scope
            entry (Scoping › Scope) decides what scans may reach.
          </p>

          {attribution.evidence.length > 0 && (
            <div className="space-y-1.5">
              <p className="font-medium">Why the platform thinks it may be yours</p>
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
            </div>
          )}

          {can(Permission.AssetsWrite) && (
            <div className="space-y-2">
              <p className="font-medium">Is it yours?</p>
              <ul className="space-y-2" role="group" aria-label="Decide ownership">
                {[
                  ...decisionsFor(attribution.state),
                  ...(attribution.human_decided && attribution.state !== 'needs_review'
                    ? (['needs_review'] as AttributionDecision[])
                    : []),
                ].map((d) => (
                  <li key={d} className="flex flex-col gap-1 sm:flex-row sm:items-start sm:gap-3">
                    <Button
                      size="sm"
                      variant={d === 'confirmed' ? 'default' : 'outline'}
                      className="h-7 shrink-0 sm:w-64 sm:justify-start"
                      disabled={saving}
                      aria-describedby={`decision-hint-${d}`}
                      onClick={() => onDecide(d)}
                    >
                      {saving && <Loader2 className="me-1 h-3 w-3 animate-spin" />}
                      {DECISION_LABEL[d]}
                    </Button>
                    <span id={`decision-hint-${d}`} className="text-xs text-muted-foreground">
                      {DECISION_HINT[d]}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : null}
      <ScopeEntryDialog
        open={draft !== null}
        draft={draft ?? undefined}
        onOpenChange={(o) => !o && setDraft(null)}
        onCreated={() => void mutate()}
      />
    </DetailSection>
  )
}
