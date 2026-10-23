'use client'

import * as React from 'react'
import { AlertOctagon } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * Class of the KEV (known exploited vulnerability) badge: a solid danger pill.
 * Solid, so it reads as a fact about the vulnerability and never as a
 * severity (soft, dotted) or a priority class (ink box). Exported for the
 * rare trigger that needs the class on its own element.
 */
export const KEV_BADGE_CLASS =
  'inline-flex w-fit shrink-0 items-center gap-1 whitespace-nowrap rounded-full bg-destructive px-1.5 py-0.5 text-[11px] font-semibold leading-none text-destructive-foreground'

export type KevBadgeProps = React.ComponentProps<'span'> & {
  /** Replace the "KEV" label (a count, "KEV 3"). */
  label?: React.ReactNode
}

/** The one KEV badge: lists, drawers, dashboards. The text is always present. */
export const KevBadge = React.forwardRef<HTMLSpanElement, KevBadgeProps>(function KevBadge(
  { label, className, ...props },
  ref
) {
  const { t } = useTranslation()
  return (
    <span ref={ref} data-slot="kev-badge" className={cn(KEV_BADGE_CLASS, className)} {...props}>
      <AlertOctagon className="size-2.5" aria-hidden />
      {label ?? t('findings.list.kev', 'KEV')}
    </span>
  )
})
