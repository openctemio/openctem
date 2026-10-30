'use client'

/**
 * Refused targets of a scan form, grouped by reason (RFC-054 §6.4), shared by
 * the Targets and Review steps: the readiness line (how many targets, how
 * many ready, how many blocked) and one collapsible group per reason with its
 * count, a few examples, "Show all", and the server's ranked remedies for the
 * whole group (run on my sensor, verify the domain, lower the intensity,
 * remove), the first one primary. Every action goes through the normal route
 * (switching the sensor preference, verifying a domain, lowering the scan's
 * intensity, approving or activating an entry, removing targets): nothing
 * here grants anything, and the scope check runs again after each.
 */

import { useState } from 'react'
import Link from '@/components/link'
import {
  ChevronDown,
  Gauge,
  Loader2,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import {
  ScopeFixButtons,
  ScopePendingEntry,
  scopeRefusalLabel,
  type ApiScopeCheckResult,
} from '@/features/scope'
import { safeInternalHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'
import { VerifyDomainDialog } from '@/features/attack-surface/components/easm-verify-domain-dialog'
import {
  groupRefusals,
  internalAddressOf,
  type GroupRemedy,
  type RefusalGroup,
} from '../../lib/refusal-groups'
import { intensityForTier, type ProbeTier } from '../../lib/scan-intensity'

/** Examples shown before "Show all". */
export const GROUP_EXAMPLES = 5

interface RefusalGroupsProps {
  results: ApiScopeCheckResult[]
  /** The probe tier the check ran at. */
  probeTier?: number
  sensorPreference?: string
  /** Remove these targets from the scan. */
  onRemove: (targets: string[]) => void
  /** Run the scan on the organization's own sensors. */
  onUseOwnSensors?: () => void
  /**
   * Lower the scan's intensity to this tier. Offered only when given and
   * canLowerIntensity allows the tier (the chosen workflow still fits it).
   */
  onLowerIntensity?: (tier: ProbeTier) => void
  canLowerIntensity?: (tier: ProbeTier) => boolean
  /** Re-run the scope check (after a fix). */
  onRecheck: () => void
}

export function RefusalGroups({
  results,
  probeTier,
  sensorPreference,
  onRemove,
  onUseOwnSensors,
  onLowerIntensity,
  canLowerIntensity,
  onRecheck,
}: RefusalGroupsProps) {
  const groups = groupRefusals(results)
  if (groups.length === 0) return null
  return (
    <div className="min-w-0 divide-y border-y" data-testid="refusal-groups">
      {groups.map((g) => (
        <GroupSection
          key={g.key}
          group={g}
          probeTier={probeTier}
          sensorPreference={sensorPreference}
          onRemove={onRemove}
          onUseOwnSensors={sensorPreference === 'tenant' ? undefined : onUseOwnSensors}
          onLowerIntensity={onLowerIntensity}
          canLowerIntensity={canLowerIntensity}
          onRecheck={onRecheck}
        />
      ))}
    </div>
  )
}

interface ReadinessLineProps {
  /** Targets the scan sends. */
  total: number
  ready: number
  blocked: number
  /** The first answer is on its way. */
  checking?: boolean
  /** Asset groups, whose members are checked when the scan runs. */
  groupCount?: number
}

/**
 * One line, no card: "3 targets, 2 ready, 1 blocked", each count with a
 * small status dot, separated by space (never a middle dot).
 */
export function ReadinessLine({
  total,
  ready,
  blocked,
  checking,
  groupCount = 0,
}: ReadinessLineProps) {
  const { t } = useTranslation()
  return (
    <p
      className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-1 text-sm"
      aria-live="polite"
      data-testid="readiness-line"
    >
      <span className="font-medium">
        {total === 1
          ? t('scans.readiness.targetsOne')
          : t('scans.readiness.targetsMany', undefined, { count: total.toLocaleString() })}
      </span>
      {groupCount > 0 && (
        <span className="font-medium">
          {groupCount === 1
            ? t('scans.readiness.groupsOne')
            : t('scans.readiness.groupsMany', undefined, { count: groupCount })}
        </span>
      )}
      {checking ? (
        <span className="flex items-center gap-1.5 text-muted-foreground">
          <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
          {t('scans.readiness.checking')}
        </span>
      ) : (
        <>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 shrink-0 rounded-full bg-success" aria-hidden />
            {t('scans.readiness.ready', undefined, { count: ready })}
          </span>
          <span className="flex items-center gap-1.5">
            <span
              className={cn(
                'h-2 w-2 shrink-0 rounded-full',
                blocked > 0 ? 'bg-warning' : 'bg-muted-foreground/40'
              )}
              aria-hidden
            />
            {t('scans.readiness.blocked', undefined, { count: blocked })}
          </span>
        </>
      )}
    </p>
  )
}

function useGroupTitle(g: RefusalGroup): string {
  const { t } = useTranslation()
  const count = g.results.length
  const vars = { count, pattern: g.rule?.pattern ?? '' }
  switch (g.kind) {
    case 'proof':
      return t('scans.groups.proof', undefined, vars)
    case 'platform':
      return t(
        'scans.groups.platform',
        '{count} are program targets shared sensors never scan',
        vars
      )
    case 'zone':
      return t(
        'scans.groups.zone',
        '{count} resolve to private addresses outside every scan zone',
        vars
      )
    case 'unresolved':
      return t('scans.groups.unresolved', '{count} do not resolve in DNS', vars)
    case 'entry':
      if (g.code === 'entry_pending')
        return t('scans.groups.entryPending', '{count} wait for {pattern} to be approved', vars)
      if (g.code === 'entry_inactive')
        return t(
          'scans.groups.entryInactive',
          '{count} are covered by {pattern}, which is deactivated',
          vars
        )
      return t(
        'scans.groups.entryExpired',
        '{count} were covered by {pattern}, which expired',
        vars
      )
    case 'scope':
      return t('scans.groups.scope', '{count} are out of scope', vars)
    case 'ownership':
      return t('scans.groups.ownership', '{count} are excluded or not confirmed as yours', vars)
    case 'access':
      return t('scans.groups.access', '{count} are outside the assets you may scan', vars)
    default:
      return t(
        'scans.groups.invalid',
        '{count} are not valid targets or not allowed by the platform',
        vars
      )
  }
}

function useGroupHint(g: RefusalGroup): string {
  const { t } = useTranslation()
  switch (g.kind) {
    case 'proof':
      return t(
        'scans.groups.proofHint',
        "The platform's shared sensors scan only domains your organization verified. Run the scan on your own sensor, verify the domain, or remove these targets."
      )
    case 'platform':
      return t(
        'scans.groups.platformHint',
        'Only bug-bounty program entries cover these targets. Run the scan on your own sensor, or remove them.'
      )
    case 'zone':
      return t(
        'scans.groups.zoneHint',
        'Scanning an internal address would hit your own network, so a scan zone must say which of your sensors may reach it.'
      )
    case 'unresolved':
      return t(
        'scans.groups.unresolvedHint',
        'The platform found no DNS record for these names. Fix the DNS record, or scan their addresses instead.'
      )
    case 'entry':
      return t(
        'scans.groups.entryHint',
        'The scope entry exists, but it does not authorize scans until it is in effect.'
      )
    case 'scope':
      return t(
        'scans.groups.scopeHint',
        'No scope entry covers these targets for this kind of scan. Add them in Scoping, or remove them.'
      )
    case 'ownership':
      return t(
        'scans.groups.ownershipHint',
        'Your organization excluded these names, or their ownership waits for review.'
      )
    case 'access':
      return t('scans.groups.accessHint', 'You may scan only the assets in your data scope.')
    default:
      return t('scans.groups.invalidHint', 'These targets cannot be scanned. Remove them.')
  }
}

function GroupSection({
  group,
  probeTier,
  sensorPreference,
  onRemove,
  onUseOwnSensors,
  onLowerIntensity,
  canLowerIntensity,
  onRecheck,
}: {
  group: RefusalGroup
  probeTier?: number
  sensorPreference?: string
  onRemove: (targets: string[]) => void
  onUseOwnSensors?: () => void
  onLowerIntensity?: (tier: ProbeTier) => void
  canLowerIntensity?: (tier: ProbeTier) => boolean
  onRecheck: () => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(true)
  const [all, setAll] = useState(false)
  const [verifying, setVerifying] = useState<string | null>(null)
  const title = useGroupTitle(group)
  const hint = useGroupHint(group)
  const shown = all ? group.results : group.results.slice(0, GROUP_EXAMPLES)
  const targets = group.results.map((r) => r.target ?? '').filter(Boolean)
  const bodyId = `refusal-group-${group.key.replace(/[^a-z0-9]/gi, '-')}`
  const zonesHref = safeInternalHref('/sensors?tab=zones')
  const scopeHref = safeInternalHref('/scope?tab=targets')

  // The server's remedies the form can act on here, in its order; remove is
  // always possible, so it is kept (last) even when the answer predates it.
  const usable = (r: GroupRemedy): boolean => {
    switch (r.action) {
      case 'run_on_tenant_sensor':
        return !!onUseOwnSensors
      case 'verify_domain':
        return r.domains.length > 0
      case 'lower_intensity':
        return (
          !!onLowerIntensity &&
          r.tier !== undefined &&
          (canLowerIntensity?.(r.tier as ProbeTier) ?? true)
        )
      default:
        return true
    }
  }
  const remedies = group.remedies.filter(usable)
  if (!remedies.some((r) => r.action === 'remove')) remedies.push({ action: 'remove', domains: [] })

  const remedyButton = (r: GroupRemedy, i: number) => {
    const primary = i === 0
    const common = {
      type: 'button' as const,
      size: 'sm' as const,
      variant: primary ? ('default' as const) : ('outline' as const),
      className: 'h-8 max-sm:min-h-11',
    }
    switch (r.action) {
      case 'run_on_tenant_sensor':
        return (
          <Button key={r.action} {...common} onClick={onUseOwnSensors}>
            <ServerCog className="me-1.5 h-3.5 w-3.5" aria-hidden />
            {t('scans.groups.remedy.runOnTenantSensor')}
          </Button>
        )
      case 'verify_domain':
        return r.domains.map((domain, j) => (
          <Button
            key={`verify-${domain}`}
            {...common}
            variant={primary && j === 0 ? 'default' : 'outline'}
            onClick={() => setVerifying(domain)}
          >
            <ShieldCheck className="me-1.5 h-3.5 w-3.5" aria-hidden />
            {t('scans.groups.remedy.verifyDomain', undefined, { domain })}
          </Button>
        ))
      case 'lower_intensity':
        return (
          <Button
            key={r.action}
            {...common}
            onClick={() => onLowerIntensity?.(r.tier as ProbeTier)}
          >
            <Gauge className="me-1.5 h-3.5 w-3.5" aria-hidden />
            {t('scans.groups.remedy.lowerIntensity', undefined, {
              level: t(`scans.intensity.${intensityForTier(r.tier as ProbeTier)}`),
            })}
          </Button>
        )
      default:
        return (
          <Button key={r.action} {...common} onClick={() => onRemove(targets)}>
            <Trash2 className="me-1.5 h-3.5 w-3.5" aria-hidden />
            {targets.length === 1
              ? t('scans.groups.removeOne', 'Remove this target')
              : t('scans.groups.removeMany', 'Remove these {count} targets', {
                  count: targets.length,
                })}
          </Button>
        )
    }
  }

  return (
    <section
      className="min-w-0 py-3"
      aria-label={title}
      data-testid={`refusal-group-${group.kind}`}
    >
      <button
        type="button"
        className="flex min-h-11 w-full min-w-0 items-start gap-2 text-start"
        aria-expanded={open}
        aria-controls={bodyId}
        onClick={() => setOpen((o) => !o)}
      >
        <ChevronDown
          className={cn(
            'mt-0.5 h-4 w-4 shrink-0 text-muted-foreground transition-transform',
            !open && '-rotate-90'
          )}
          aria-hidden
        />
        <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
        <span className="min-w-0 flex-1 text-sm font-medium">{title}</span>
      </button>
      {open && (
        <div id={bodyId} className="min-w-0 space-y-2 ps-6 pt-1">
          <p className="text-xs text-muted-foreground">{hint}</p>
          <ul className="min-w-0 divide-y" aria-label={t('scans.groups.targets', 'Targets')}>
            {shown.map((r, i) => (
              <GroupRow key={`${r.target}-${i}`} result={r} kind={group.kind} />
            ))}
          </ul>
          {group.results.length > GROUP_EXAMPLES && (
            <Button
              type="button"
              variant="link"
              size="sm"
              className="h-auto p-0 text-xs"
              onClick={() => setAll((a) => !a)}
            >
              {all
                ? t('scans.groups.showFewer', 'Show fewer')
                : t('scans.groups.showAll', 'Show all {count}', { count: group.results.length })}
            </Button>
          )}
          <div className="flex flex-wrap items-center gap-2 pt-1" data-testid="refusal-remedies">
            {remedies.flatMap((r, i) => remedyButton(r, i))}
            {group.kind === 'entry' && group.code === 'entry_pending' && group.rule?.id ? (
              <ScopePendingEntry
                entryId={group.rule.id}
                probeTier={probeTier}
                sensorPreference={sensorPreference}
                onApplied={onRecheck}
              />
            ) : group.kind === 'entry' && group.fixes.length > 0 ? (
              <ScopeFixButtons
                fixes={group.fixes}
                rule={group.rule}
                onApplied={onRecheck}
                size="sm"
              />
            ) : null}
            {group.kind === 'zone' && zonesHref && (
              <Button
                asChild
                type="button"
                size="sm"
                variant="outline"
                className="h-8 max-sm:min-h-11"
              >
                <Link href={zonesHref}>{t('scans.groups.setUpZone', 'Set up a scan zone')}</Link>
              </Button>
            )}
            {group.kind === 'scope' && scopeHref && (
              <Button
                asChild
                type="button"
                size="sm"
                variant="outline"
                className="h-8 max-sm:min-h-11"
              >
                <Link href={scopeHref}>{t('scans.groups.openScope', 'Open Scoping')}</Link>
              </Button>
            )}
          </div>
        </div>
      )}
      <VerifyDomainDialog
        domain={verifying}
        onOpenChange={(o) => !o && setVerifying(null)}
        onChanged={onRecheck}
      />
    </section>
  )
}

/** One refused target, compact: its name and, for a private address, why. */
function GroupRow({ result, kind }: { result: ApiScopeCheckResult; kind: RefusalGroup['kind'] }) {
  const { t } = useTranslation()
  const target = result.target ?? ''
  const addr = kind === 'zone' ? internalAddressOf(result) : undefined
  const isHost = addr !== undefined && addr !== target
  let detail: string | undefined
  if (kind === 'zone' && result.code === 'zone_none') {
    detail = addr
      ? isHost
        ? t(
            'scans.groups.resolvesTo',
            'Resolves to {addr}, an internal address: scanning it would hit your own network.',
            { addr }
          )
        : t(
            'scans.groups.isInternal',
            '{addr} is an internal address: scanning it would hit your own network.',
            { addr }
          )
      : t('scans.groups.noZone', 'No scan zone covers this target.')
  } else if (kind !== 'proof' && kind !== 'entry') {
    detail = scopeRefusalLabel(t, result.code)
  }
  return (
    <li className="min-w-0 py-1.5">
      <span className="block break-all font-mono text-xs" title={target}>
        {target}
      </span>
      {detail && <span className="block text-xs text-muted-foreground">{detail}</span>}
    </li>
  )
}
