'use client'

/**
 * Refused targets on the Review step, grouped by reason (RFC-054 §6.4): one
 * collapsible group per reason with its count, a few examples, "Show all",
 * and one action for the whole group. Every action goes through the normal
 * route (switching the sensor preference, verifying a domain, approving or
 * activating an entry, removing targets): nothing here grants anything, and
 * the scope check runs again after each.
 */

import { useState } from 'react'
import Link from '@/components/link'
import { ChevronDown, ServerCog, ShieldAlert, Trash2 } from 'lucide-react'
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
import {
  canVerify,
  groupRefusals,
  internalAddressOf,
  ownSensorHelps,
  type RefusalGroup,
} from '../../lib/refusal-groups'

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
  /** Re-run the scope check (after a fix). */
  onRecheck: () => void
}

export function RefusalGroups({
  results,
  probeTier,
  sensorPreference,
  onRemove,
  onUseOwnSensors,
  onRecheck,
}: RefusalGroupsProps) {
  const groups = groupRefusals(results)
  if (groups.length === 0) return null
  return (
    <div className="space-y-2">
      {groups.map((g) => (
        <GroupCard
          key={g.key}
          group={g}
          probeTier={probeTier}
          sensorPreference={sensorPreference}
          onRemove={onRemove}
          onUseOwnSensors={sensorPreference === 'tenant' ? undefined : onUseOwnSensors}
          onRecheck={onRecheck}
        />
      ))}
    </div>
  )
}

function useGroupTitle(g: RefusalGroup): string {
  const { t } = useTranslation()
  const count = g.results.length
  const vars = { count, pattern: g.rule?.pattern ?? '' }
  switch (g.kind) {
    case 'proof':
      return t('scans.groups.proof', '{count} need a verified domain for shared sensors', vars)
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

function useGroupHint(g: RefusalGroup, probeTier?: number): string {
  const { t } = useTranslation()
  switch (g.kind) {
    case 'proof':
      return (probeTier ?? 1) >= 2
        ? t(
            'scans.groups.proofIntrusiveHint',
            'Intrusive checks need a verified domain of your organization on every sensor. Verify the domain, or remove these targets.'
          )
        : t(
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

function GroupCard({
  group,
  probeTier,
  sensorPreference,
  onRemove,
  onUseOwnSensors,
  onRecheck,
}: {
  group: RefusalGroup
  probeTier?: number
  sensorPreference?: string
  onRemove: (targets: string[]) => void
  onUseOwnSensors?: () => void
  onRecheck: () => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(true)
  const [all, setAll] = useState(false)
  const title = useGroupTitle(group)
  const hint = useGroupHint(group, probeTier)
  const shown = all ? group.results : group.results.slice(0, GROUP_EXAMPLES)
  const targets = group.results.map((r) => r.target ?? '').filter(Boolean)
  const bodyId = `refusal-group-${group.key.replace(/[^a-z0-9]/gi, '-')}`
  const intrusive = (probeTier ?? 1) >= 2
  const verifyFixes = canVerify(group)
    ? group.domains.map((domain) => ({ action: 'verify_domain', domain }))
    : []
  const zonesHref = safeInternalHref('/sensors?tab=zones')
  const scopeHref = safeInternalHref('/scope?tab=targets')

  return (
    <section
      className="min-w-0 rounded-lg border border-warning/50"
      aria-label={title}
      data-testid={`refusal-group-${group.kind}`}
    >
      <button
        type="button"
        className="flex w-full min-w-0 items-start gap-2 p-3 text-start"
        aria-expanded={open}
        aria-controls={bodyId}
        onClick={() => setOpen((o) => !o)}
      >
        <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-medium">{title}</span>
          <span className="block text-xs text-muted-foreground">{hint}</span>
        </span>
        <ChevronDown
          className={cn('mt-0.5 h-4 w-4 shrink-0 transition-transform', open && 'rotate-180')}
          aria-hidden
        />
      </button>
      {open && (
        <div id={bodyId} className="min-w-0 space-y-3 border-t px-3 pt-2 pb-3">
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
          <div className="flex flex-wrap items-center gap-2">
            {onUseOwnSensors && ownSensorHelps(group) && !intrusive && (
              <Button type="button" size="sm" className="h-8" onClick={onUseOwnSensors}>
                <ServerCog className="me-1.5 h-3.5 w-3.5" aria-hidden />
                {t('scans.groups.useOwnSensor', 'Run on your own sensor')}
              </Button>
            )}
            {group.kind === 'proof' && verifyFixes.length > 0 && (
              <ScopeFixButtons fixes={verifyFixes} onApplied={onRecheck} size="sm" />
            )}
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
              <Button asChild type="button" size="sm" variant="outline" className="h-8">
                <Link href={zonesHref}>{t('scans.groups.setUpZone', 'Set up a scan zone')}</Link>
              </Button>
            )}
            {group.kind === 'scope' && scopeHref && (
              <Button asChild type="button" size="sm" variant="outline" className="h-8">
                <Link href={scopeHref}>{t('scans.groups.openScope', 'Open Scoping')}</Link>
              </Button>
            )}
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="h-8"
              onClick={() => onRemove(targets)}
            >
              <Trash2 className="me-1.5 h-3.5 w-3.5" aria-hidden />
              {targets.length === 1
                ? t('scans.groups.removeOne', 'Remove this target')
                : t('scans.groups.removeMany', 'Remove these {count} targets', {
                    count: targets.length,
                  })}
            </Button>
          </div>
        </div>
      )}
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
