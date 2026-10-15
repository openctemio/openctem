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
import { useTranslation } from '@/context/i18n-provider'
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
  attributionStateLabel,
  type AttributionT,
  decisionsFor,
  describeEvidence,
  scanStanding,
  scopeStandingText,
  type AttributionDecision,
} from '../lib/attribution'

/** Button labels: what the person is saying about the asset. */
export function decisionLabel(t: AttributionT, d: AttributionDecision): string {
  switch (d) {
    case 'confirmed':
      return t('assets.attribution.decision.confirmed', 'Ours')
    case 'rejected':
      return t('assets.attribution.decision.rejected', 'Not ours')
    case 'dependency':
      return t('assets.attribution.decision.dependency', 'Ours, on third-party infrastructure')
    case 'monitor_only':
      return t('assets.attribution.decision.monitorOnly', 'Watch only')
    default:
      return t('assets.attribution.decision.undo', 'Undo the decision')
  }
}

/** What each decision does, shown next to its button. */
export function decisionHint(t: AttributionT, d: AttributionDecision): string {
  switch (d) {
    case 'confirmed':
      return t(
        'assets.attribution.decisionHint.confirmed',
        'It belongs to your organization and stays in the inventory. A domain or address also gets its exact scope entry, unless your organization turned this off or uses Strict scan approval.'
      )
    case 'rejected':
      return t(
        'assets.attribution.decisionHint.rejected',
        'It is not yours. It leaves the inventory, and scans never touch it or the names below it.'
      )
    case 'dependency':
      return t(
        'assets.attribution.decisionHint.dependency',
        'Your name on someone else’s servers (CDN, SaaS, hosting). Only passive and takeover checks run.'
      )
    case 'monitor_only':
      return t(
        'assets.attribution.decisionHint.monitorOnly',
        'Keep watching it passively (certificates, DNS). It is never actively scanned.'
      )
    default:
      return t(
        'assets.attribution.decisionHint.undo',
        'Clear the decision and let the evidence decide again.'
      )
  }
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
  const { t } = useTranslation()
  const { attribution, isLoading, error, mutate } = useAssetAttribution(assetId)
  const { decide, saving } = useDecideAttribution(assetId)
  const { can } = usePermissions()
  const [draft, setDraft] = useState<ScopeEntryDraft | null>(null)

  const onDecide = async (state: AttributionDecision) => {
    try {
      const next = await decide(state)
      await mutate(next, { revalidate: false })
      toast.success(
        t('assets.attribution.toast.set', 'Ownership set to {state}', {
          state: attributionStateLabel(t, state).toLowerCase(),
        })
      )
      // Confirming also adds the asset's exact scope entry (unless turned off
      // or Strict approval): say so when it did, and refresh what covers it.
      const added = next.scope?.entries?.find((en) => en.outcome === 'added')
      if (added) {
        toast.success(
          t('assets.attribution.toast.scopeAdded', 'Added {pattern} to scope', {
            pattern: added.pattern ?? added.name ?? '',
          })
        )
        await mutate()
      }
    } catch (e) {
      toast.error(
        e instanceof Error
          ? e.message
          : t('assets.attribution.toast.failed', 'Could not save the decision')
      )
    }
  }

  const scope = attribution ? scopeStandingText(t, attribution) : null
  const canAddScope = can(Permission.ScopeWrite) && !!assetName

  return (
    <DetailSection title={t('assets.attribution.title', 'Ownership and scope')} icon={ShieldCheck}>
      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-5 w-1/3" />
          <Skeleton className="h-5 w-3/4" />
        </div>
      ) : error ? (
        <ErrorState
          title={t('assets.attribution.errorTitle', 'ownership')}
          error={error}
          onRetry={() => mutate()}
        />
      ) : attribution ? (
        <div className="space-y-4 text-sm">
          <dl className="grid grid-cols-[6.5rem_1fr] gap-x-3 gap-y-2">
            <dt className="text-muted-foreground">{t('assets.attribution.ours', 'Ours?')}</dt>
            <dd className="flex min-w-0 flex-wrap items-center gap-2">
              <Badge
                variant="outline"
                className={cn('border-transparent', ATTRIBUTION_STATE_CLASS[attribution.state])}
              >
                {attributionStateLabel(t, attribution.state)}
              </Badge>
              {attribution.recorded && !attribution.human_decided && (
                <span className="text-muted-foreground tabular-nums">
                  {t('assets.attribution.confidence', '{n}% confidence', {
                    n: attribution.confidence,
                  })}
                </span>
              )}
              {attribution.human_decided && attribution.decided_at && (
                <span className="text-muted-foreground">
                  {t('assets.attribution.decided', 'Decided')}{' '}
                  <RelativeTime date={attribution.decided_at} />
                </span>
              )}
              {!attribution.recorded && (
                <span className="text-muted-foreground">
                  {t(
                    'assets.attribution.legacy',
                    'In the inventory before discovery evidence was kept'
                  )}
                </span>
              )}
            </dd>
            <dt className="text-muted-foreground">{t('assets.attribution.scans', 'Scans')}</dt>
            <dd className="min-w-0 space-y-1">
              {scope && <p className={cn(scope.ok ? 'text-foreground' : '')}>{scope.text}</p>}
              {/* The ownership side of the answer; the scope line above already
                  says "no entry covers it" when that is the reason. */}
              {!(
                scope &&
                ['unattributed', 'out_of_scope'].includes(
                  attribution.active_checks_blocked_by ?? ''
                )
              ) && <p className="text-muted-foreground">{scanStanding(t, attribution)}</p>}
              {scope && !scope.ok && scope.canAdd && canAddScope && (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7"
                  onClick={() =>
                    setDraft({
                      pattern: assetName,
                      target_type:
                        assetType === 'ip_address' || assetType === 'repository'
                          ? assetType
                          : undefined,
                    })
                  }
                >
                  {t('assets.attribution.addToScope', 'Add to scope')}
                </Button>
              )}
            </dd>
          </dl>

          <p className="flex gap-2 rounded-md bg-muted/50 px-3 py-2 text-xs text-muted-foreground">
            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
            {t(
              'assets.attribution.note',
              'Confirming a domain or address as yours also adds its exact scope entry, unless your organization turned this off or uses Strict scan approval. Scans reach only what a scope entry (Scoping › Scope) covers.'
            )}
          </p>

          {attribution.evidence.length > 0 && (
            <div className="space-y-1.5">
              <p className="font-medium">
                {t('assets.attribution.why', 'Why the platform thinks it may be yours')}
              </p>
              <ul
                className="space-y-1.5"
                aria-label={t('assets.attribution.evidenceLabel', 'Evidence')}
              >
                {attribution.evidence.map((e) => (
                  <li key={`${e.rule}-${e.source}`} className="flex gap-2">
                    <span className="text-muted-foreground tabular-nums">
                      {Math.round(e.weight * 100)}%
                    </span>
                    <span className="min-w-0 break-words">{describeEvidence(t, e)}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {can(Permission.AssetsWrite) && (
            <div className="space-y-2">
              <p className="font-medium">{t('assets.attribution.question', 'Is it yours?')}</p>
              <ul
                className="space-y-2"
                role="group"
                aria-label={t('assets.attribution.decideLabel', 'Decide ownership')}
              >
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
                      {decisionLabel(t, d)}
                    </Button>
                    <span id={`decision-hint-${d}`} className="text-xs text-muted-foreground">
                      {decisionHint(t, d)}
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
