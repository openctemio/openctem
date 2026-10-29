'use client'

import { safeInternalHref } from '@/lib/safe-href'
import Link from '@/components/link'
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { PriorityBadge } from '@/components/ui/priority-badge'
import { useTranslation } from '@/context/i18n-provider'
import { MetricStrip, type MetricStripItem } from '@/features/shared/components/metric-strip'
import { STATUS_TONE_FILL } from '@/lib/status-colors'
import { cn } from '@/lib/utils'
import type { CveExposure } from '../../types/exposure'
import { cveFindingsHref, statusBuckets } from '../../lib/vuln-page'

const PRIORITIES = ['P0', 'P1', 'P2', 'P3'] as const

/**
 * The impact in the caller's scope as five tiles; each opens the findings
 * list that counts it (research/244: at most five tiles, a number earns a
 * tile only when it opens its list).
 */
export function ImpactStrip({ cve, exposure }: { cve: string; exposure: CveExposure }) {
  const { t } = useTranslation()
  const { findings, assets } = exposure
  const open = { state: 'open' }
  const items: MetricStripItem[] = [
    {
      key: 'findings',
      label: t('vulnPage.impact.findings', 'Active findings'),
      value: findings.active,
      hint: t('vulnPage.impact.ofTotal', 'of {total}', { total: findings.total.toLocaleString() }),
      href: cveFindingsHref(cve, open),
    },
    {
      key: 'assets',
      label: t('vulnPage.impact.assets', 'Assets impacted'),
      value: assets.impacted,
      detail: t('vulnPage.impact.internetFacing', '{count} internet-facing', {
        count: assets.internet_facing.toLocaleString(),
      }),
      href: cveFindingsHref(cve, { ...open, group: 'asset_id' }),
    },
    {
      key: 'crown',
      label: t('vulnPage.impact.crownJewels', 'Crown jewels impacted'),
      value: assets.crown_jewels,
      tone: 'danger',
      href: cveFindingsHref(cve, { ...open, asset_crown_jewel: 'true' }),
    },
    {
      key: 'priority',
      label: t('vulnPage.impact.priority', 'Worst priority'),
      value: findings.worst_priority ? (
        <PriorityBadge priorityClass={findings.worst_priority} className="align-middle" />
      ) : (
        t('vulnPage.impact.notPrioritized', 'Not prioritized')
      ),
      detail: (
        <span
          role="list"
          className="flex flex-wrap items-center gap-3"
          aria-label={t('vulnPage.impact.byPriority', 'Active findings by priority')}
        >
          {PRIORITIES.map((p) => (
            <span role="listitem" key={p} className="flex items-center gap-1 tabular-nums">
              <PriorityBadge priorityClass={p} />
              <span>{(findings.by_priority[p] ?? 0).toLocaleString()}</span>
            </span>
          ))}
        </span>
      ),
      href: findings.worst_priority
        ? cveFindingsHref(cve, { ...open, priority_class: findings.worst_priority })
        : cveFindingsHref(cve, open),
    },
    {
      key: 'tasks',
      label: t('vulnPage.impact.inTasks', 'In remediation tasks'),
      value: findings.in_task,
      hint: t('vulnPage.impact.ofActive', 'of {total}', {
        total: findings.active.toLocaleString(),
      }),
      detail: t('vulnPage.impact.notInTask', '{count} not yet in a task', {
        count: findings.not_in_task.toLocaleString(),
      }),
      href: '/remediation/tasks',
    },
  ]
  return (
    <section aria-label={t('vulnPage.impact.label', 'Impact in your scope')}>
      <MetricStrip items={items} />
    </section>
  )
}

/** "Status of the N findings": one stacked bar; every segment opens its list. */
export function StatusCard({ cve, exposure }: { cve: string; exposure: CveExposure }) {
  const { t } = useTranslation()
  const buckets = statusBuckets(cve, exposure.findings.by_status)
  const total = exposure.findings.total
  const label = (key: string) =>
    t(
      `vulnPage.status.${key}`,
      {
        open: 'Open',
        fixed: 'Fixed',
        accepted: 'Accepted',
        false_positive: 'False positive',
        duplicate: 'Duplicate',
        other: 'Other',
      }[key] as string
    )
  return (
    <Card data-slot="status-card">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">
          {t('vulnPage.status.title', 'Status of the {count} findings', {
            count: total.toLocaleString(),
          })}
        </CardTitle>
        <CardAction className="self-center">
          <span className="text-xs text-muted-foreground">
            {t('vulnPage.status.hint', 'Each segment opens its list')}
          </span>
        </CardAction>
      </CardHeader>
      <CardContent>
        {total === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t('vulnPage.status.none', 'No finding of this vulnerability in your scope.')}
          </p>
        ) : (
          <>
            <div
              className="flex h-3 gap-0.5 overflow-hidden rounded-sm"
              // The legend below carries the counts and the links for
              // assistive tech and the keyboard; the bar is for the eye and the mouse.
              aria-hidden
            >
              {buckets.map((b) => (
                <Link
                  key={b.key}
                  href={safeInternalHref(b.href) ?? '/findings'}
                  tabIndex={-1}
                  title={`${label(b.key)} ${b.count}`}
                  className={cn('block h-full hover:opacity-80', STATUS_TONE_FILL[b.tone])}
                  style={{ flexGrow: b.count, flexBasis: 0 }}
                />
              ))}
            </div>
            <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs">
              {buckets.map((b) => (
                <li key={b.key}>
                  <Link
                    href={safeInternalHref(b.href) ?? '/findings'}
                    className="inline-flex items-center gap-1.5 text-muted-foreground hover:text-foreground hover:underline"
                  >
                    <i
                      className={cn(
                        'inline-block h-2.5 w-2.5 rounded-sm',
                        STATUS_TONE_FILL[b.tone]
                      )}
                      aria-hidden
                    />
                    {label(b.key)}
                    <b className="font-semibold tabular-nums text-foreground">
                      {b.count.toLocaleString()}
                    </b>
                  </Link>
                </li>
              ))}
            </ul>
          </>
        )}
      </CardContent>
    </Card>
  )
}
