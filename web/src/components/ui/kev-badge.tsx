'use client'

import * as React from 'react'
import { Zap } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * Class of the KEV (known exploited vulnerability) chip: neutral, with only
 * the bolt in the danger colour. KEV is a supporting fact about the
 * vulnerability, so it never out-shouts the priority box. Exported for the
 * rare trigger that needs the class on its own element.
 */
export const KEV_BADGE_CLASS =
  'inline-flex w-fit shrink-0 items-center gap-1 whitespace-nowrap rounded-sm border border-border bg-transparent px-1.5 py-0.5 text-xs font-semibold leading-none text-foreground'

export type KevBadgeProps = React.ComponentProps<'span'> & {
  /** Replace the "KEV" label (a count, "KEV 3"). */
  label?: React.ReactNode
  /** The CISA due date has passed: the text turns red and reads "· past due". */
  pastDue?: boolean
  /** Known ransomware use: reads "· ransomware". */
  ransomware?: boolean
}

/** The one KEV chip: lists, drawers, dashboards. The text is always present. */
export const KevBadge = React.forwardRef<HTMLSpanElement, KevBadgeProps>(function KevBadge(
  { label, pastDue, ransomware, className, ...props },
  ref
) {
  const { t } = useTranslation()
  return (
    <span
      ref={ref}
      data-past-due={pastDue ? 'true' : undefined}
      data-ransomware={ransomware ? 'true' : undefined}
      className={cn(KEV_BADGE_CLASS, pastDue && 'text-destructive', className)}
      {...props}
      data-slot="kev-badge"
    >
      <Zap className="size-3 shrink-0 text-sig-icon" aria-hidden />
      {label ?? t('findings.list.kev', 'KEV')}
      {ransomware && <> · {t('findings.list.kevRansomware', 'ransomware')}</>}
      {pastDue && <> · {t('findings.list.kevPastDue', 'past due')}</>}
    </span>
  )
})
