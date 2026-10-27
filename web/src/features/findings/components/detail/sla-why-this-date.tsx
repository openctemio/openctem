'use client'

import { HelpCircle } from 'lucide-react'
import Link from '@/components/link'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/lib/permissions/hooks'
import { Permission } from '@/lib/permissions/constants'
import { formatCalendarDate } from '@/lib/format-metric'
import type { ApiSlaBasis } from '../../api/finding-api.types'

/** The lines of the explanation, in reading order (pure, unit-tested). */
export function slaWhyLines(
  b: ApiSlaBasis,
  ctx: { priorityClass?: string; severity?: string },
  t: (key: string, fallback: string, vars?: Record<string, string | number>) => string,
  fmt: (iso: string) => string
): string[] {
  const lines: string[] = []
  const policy =
    b.policy_scope === 'platform'
      ? t('findings.slaWhy.policyPlatform', 'the platform defaults (no SLA policy is set up)')
      : b.policy_scope === 'asset'
        ? t('findings.slaWhy.policyAsset', 'the asset policy {name}', { name: b.policy_name })
        : t('findings.slaWhy.policyOrg', 'the organization policy {name}', { name: b.policy_name })
  if (b.basis === 'none') {
    lines.push(
      t('findings.slaWhy.none', 'No deadline: informational findings get no SLA under {policy}.', {
        policy,
      })
    )
    return lines
  }
  lines.push(
    b.basis === 'priority'
      ? t('findings.slaWhy.windowPriority', '{days} days for priority {class}, from {policy}.', {
          days: b.days,
          class: ctx.priorityClass ?? '',
          policy,
        })
      : t('findings.slaWhy.windowSeverity', '{days} days for {severity} severity, from {policy}.', {
          days: b.days,
          severity: ctx.severity ?? '',
          policy,
        })
  )
  const start = fmt(b.clock_started_at)
  lines.push(
    b.clock_reason === 'reopened'
      ? b.last_restart_trigger === 'retest'
        ? t(
            'findings.slaWhy.clockReopenedRetest',
            'The clock restarted on {date}, when a retest found it again.',
            { date: start }
          )
        : t(
            'findings.slaWhy.clockReopened',
            'The clock restarted on {date}, when a scan found it again.',
            { date: start }
          )
      : b.clock_reason === 'recalculated'
        ? t(
            'findings.slaWhy.clockRecalculated',
            'The clock counts from {date}, when its priority went up.',
            { date: start }
          )
        : t(
            'findings.slaWhy.clockFirst',
            'The clock started on {date}, when it was first detected.',
            { date: start }
          )
  )
  if (b.restarts > 1) {
    lines.push(
      t('findings.slaWhy.restarts', 'Restarted {count} times by regressions.', {
        count: b.restarts,
      })
    )
  }
  if (b.kev_capped) {
    lines.push(
      t('findings.slaWhy.kevCap', 'Shortened to {days} days because it is in CISA KEV.', {
        days: b.kev_cap_days,
      })
    )
  }
  if (b.earlier) {
    lines.push(
      t(
        'findings.slaWhy.earlier',
        'Earlier than this window: a deadline only ever moves earlier, so an earlier date from a higher priority stays.'
      )
    )
  }
  return lines
}

/**
 * "Why this date": a small button beside the SLA deadline that opens the
 * reasons, from the API's sla_basis (the same rule that set the deadline):
 * the window and what set it, when the clock started or restarted, the KEV
 * cap, and why it can be earlier than the window. Renders nothing without
 * the block.
 */
export function SlaWhyThisDate({
  basis,
  priorityClass,
  severity,
}: {
  basis?: ApiSlaBasis
  priorityClass?: string
  severity?: string
}) {
  const { t, locale } = useTranslation()
  if (!basis) return null
  const lines = slaWhyLines(basis, { priorityClass, severity }, t, (iso) =>
    formatCalendarDate(iso, locale)
  )
  return (
    <Popover>
      <PopoverTrigger
        data-slot="sla-why"
        className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1 rounded-sm text-xs underline-offset-2 hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      >
        <HelpCircle className="size-3.5" aria-hidden />
        {t('findings.slaWhy.trigger', 'Why this date')}
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80 space-y-2 text-sm">
        <p className="font-medium">{t('findings.slaWhy.title', 'Why this date')}</p>
        <ul className="text-muted-foreground list-disc space-y-1 ps-4">
          {lines.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
        {basis.policy_scope !== 'platform' && <PoliciesLink />}
      </PopoverContent>
    </Popover>
  )
}

/** The SLA policies page, for people who may read it. */
function PoliciesLink() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  if (!can(Permission.SLARead)) return null
  return (
    <Link href="/settings/sla-policies" className="text-signal-text text-xs hover:underline">
      {t('findings.slaWhy.openPolicies', 'Open SLA policies')}
    </Link>
  )
}
