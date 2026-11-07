'use client'

// Asset liveness (api docs/architecture/asset-liveness.md): unreachable,
// unresolvable or gone, since when and which zone or sensor checked last.
// Alive and not-checked assets show nothing: the badge is for the cases
// that change what a finding on the asset means.

import { HealthStatus } from '@/components/ui/health-status'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { formatLocalized, formatRelative } from '@/lib/format-date'
import type { HealthState } from '@/lib/health-colors'
import { cn } from '@/lib/utils'
import type { AssetLiveness, AssetLivenessState } from '@/features/assets/types'

/** Liveness state -> health state: a label worth a look, gone is off. */
export const ASSET_LIVENESS_HEALTH: Record<AssetLivenessState, HealthState> = {
  alive: 'ok',
  unreachable: 'warn',
  unresolvable: 'warn',
  gone: 'off',
  unknown: 'unknown',
}

const STATE_FALLBACK: Record<AssetLivenessState, string> = {
  alive: 'Alive',
  unreachable: 'Unreachable',
  unresolvable: 'Unresolvable',
  gone: 'Gone',
  unknown: 'Not checked',
}

const REASON_FALLBACK: Record<string, string> = {
  no_answer: 'The last checks got no answer (timed out or refused), although the name resolves.',
  nxdomain: 'The name has no address (NXDOMAIN).',
  resolver_failed: "The DNS lookup failed (SERVFAIL). It may be the sensor's own DNS.",
  dangling:
    'The name points to a target with no address: a takeover risk. It stays tracked and is never marked gone.',
  nxdomain_confirmed: 'The name has had no address long enough, seen by enough sensors.',
  host_gone: 'Its host name is gone.',
}

/** Whether a liveness value is worth showing (not alive, not unchecked). */
export function livenessNotable(l: AssetLiveness | undefined | null): l is AssetLiveness {
  return !!l && l.state !== 'alive' && l.state !== 'unknown'
}

/** The sentences that explain a liveness value, in the console language. */
export function useLivenessText(l: AssetLiveness) {
  const { t, locale } = useTranslation()
  const state = t(`assetLiveness.state.${l.state}`, STATE_FALLBACK[l.state])
  const since = l.since
    ? t('assetLiveness.since', '{state} since {date}', {
        state,
        date: formatLocalized(l.since, locale),
      })
    : state
  const when = formatRelative(l.lastCheckedAt, '', locale)
  const checked = !when
    ? ''
    : l.lastCheckedBy
      ? t('assetLiveness.lastCheckedBy', 'Last checked {when} by {by}', {
          when,
          by: l.lastCheckedBy,
        })
      : t('assetLiveness.lastChecked', 'Last checked {when}', { when })
  const reason = l.reason
    ? t(`assetLiveness.reason.${l.reason}`, REASON_FALLBACK[l.reason] ?? '')
    : ''
  const effect =
    l.state === 'gone'
      ? t(
          'assetLiveness.goneFindings',
          'Open findings close as obsolete asset (not fixed) where the organization turned it on, and reopen by themselves if the asset is seen again.'
        )
      : t(
          'assetLiveness.cannotVerify',
          'Its findings stay open and their SLA keeps running: they cannot be verified while the asset does not answer.'
        )
  return { state, since, checked, reason, effect, ago: formatRelative(l.since, '', locale) }
}

interface AssetLivenessBadgeProps {
  liveness?: AssetLiveness | null
  className?: string
}

/** A compact badge for unreachable, unresolvable and gone assets. */
export function AssetLivenessBadge({ liveness, className }: AssetLivenessBadgeProps) {
  if (!livenessNotable(liveness)) return null
  return <NotableBadge liveness={liveness} className={className} />
}

function NotableBadge({ liveness, className }: { liveness: AssetLiveness; className?: string }) {
  const text = useLivenessText(liveness)
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex" data-testid="asset-liveness-badge">
          <HealthStatus
            state={ASSET_LIVENESS_HEALTH[liveness.state]}
            value={liveness.state}
            label={text.state}
            detail={text.ago ? [text.ago] : []}
            className={className}
          />
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs space-y-1 text-xs">
        <p className="font-medium">{text.since}</p>
        {text.reason && <p>{text.reason}</p>}
        {text.checked && <p className="text-muted-foreground">{text.checked}</p>}
        <p className="text-muted-foreground">{text.effect}</p>
      </TooltipContent>
    </Tooltip>
  )
}

/** The same facts as one line of prose (finding drawer, asset header). */
export function AssetLivenessLine({ liveness, className }: AssetLivenessBadgeProps) {
  if (!livenessNotable(liveness)) return null
  return <NotableLine liveness={liveness} className={className} />
}

function NotableLine({ liveness, className }: { liveness: AssetLiveness; className?: string }) {
  const { t } = useTranslation()
  const text = useLivenessText(liveness)
  return (
    <section
      aria-label={t('assetLiveness.band.aria', 'Asset liveness')}
      className={cn('rounded-lg border bg-muted/40 p-3 text-sm', className)}
      data-testid="asset-liveness-line"
    >
      <p>
        <span className="font-medium">{text.since}</span>
        {text.checked && <span className="text-muted-foreground">. {text.checked}</span>}
      </p>
      {text.reason && <p className="mt-1 text-xs text-muted-foreground">{text.reason}</p>}
      <p className="mt-1 text-xs text-muted-foreground">{text.effect}</p>
    </section>
  )
}
