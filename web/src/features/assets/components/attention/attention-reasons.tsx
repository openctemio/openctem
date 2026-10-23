'use client'

/**
 * Assets › Needs attention, the landing (research/249): the reasons as a queue
 * list under the page's one tab row. Two groups, in a fixed order: "Fix on the
 * asset" (filters of the inventory) and "Review" (their own rows). Each row is
 * one link with the reason, one line of why, and its count; a reason the
 * reader may not open (module off, no permission) is not listed. Counts come
 * from the queues' own list endpoints, so they are scoped to the reader.
 */

import { ChevronRight } from 'lucide-react'
import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { ASSET_ATTENTION_REASONS, type AttentionReasonDef } from '@/config/section-tabs'
import { useVisibleSectionTabs } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { useAttentionCount } from './use-attention-count'

const GROUPS: readonly { id: AttentionReasonDef['group']; key: string; fallback: string }[] = [
  { id: 'fix', key: 'assets.attention.group.fix', fallback: 'Fix on the asset' },
  { id: 'review', key: 'assets.attention.group.review', fallback: 'Review' },
]

function ReasonRow({ reason }: { reason: AttentionReasonDef }) {
  const { t } = useTranslation()
  const count = useAttentionCount(reason.id)
  const Icon = reason.icon
  const empty = count === 0
  return (
    <li>
      <Link
        href={reason.href}
        data-testid={`attention-reason-${reason.id}`}
        className="group flex min-h-16 items-center gap-4 rounded-lg border bg-card px-4 py-3 outline-none transition-colors hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring"
      >
        <Icon className="size-[18px] shrink-0 text-muted-foreground" aria-hidden />
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-semibold">{t(reason.labelKey, reason.label)}</span>
          <span className="block text-[13px] text-muted-foreground">
            {empty
              ? t('assets.attention.nothing', 'Nothing to do here.')
              : t(reason.whyKey, reason.why)}
          </span>
        </span>
        <span
          className={cn('flex shrink-0 items-baseline gap-1.5', empty && 'text-muted-foreground')}
          data-testid={`attention-count-${reason.id}`}
        >
          <span className="text-lg font-semibold tabular-nums">
            {count === undefined ? '' : count.toLocaleString()}
          </span>
          {count !== undefined && ' '}
          {count !== undefined && (
            <span className="text-xs text-muted-foreground">
              {t(reason.unitKey, reason.unit, { count })}
            </span>
          )}
        </span>
        <ChevronRight
          className="hidden size-4 shrink-0 text-muted-foreground sm:block rtl:rotate-180"
          aria-hidden
        />
      </Link>
    </li>
  )
}

export function AttentionReasons() {
  const { t } = useTranslation()
  const visible = useVisibleSectionTabs(ASSET_ATTENTION_REASONS)
  return (
    <div className="flex max-w-[840px] flex-col gap-6" data-testid="attention-reasons">
      <p className="text-sm text-muted-foreground">
        {t(
          'assets.attention.lede',
          'Assets missing what priority, assignment or coverage depend on. Open a reason to fix them in bulk.'
        )}
      </p>
      {GROUPS.map((group) => {
        const rows = visible.filter((r) => r.group === group.id)
        if (rows.length === 0) return null
        const headingId = `attention-group-${group.id}`
        return (
          <section key={group.id} aria-labelledby={headingId} className="flex flex-col gap-2">
            <h2 id={headingId} className="text-xs font-semibold text-muted-foreground">
              {t(group.key, group.fallback)}
            </h2>
            <ul className="flex flex-col gap-2">
              {rows.map((r) => (
                <ReasonRow key={r.id} reason={r} />
              ))}
            </ul>
          </section>
        )
      })}
    </div>
  )
}
