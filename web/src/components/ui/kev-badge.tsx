'use client'

import * as React from 'react'
import { Zap } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { SignalChip } from '@/components/ui/signal-chip'

export type KevBadgeProps = Omit<React.ComponentProps<'span'>, 'children'> & {
  /** Replace the "KEV" label (a count, "KEV 3"). */
  label?: React.ReactNode
  /** The CISA due date has passed: the text turns red and adds "past due". */
  pastDue?: boolean
  /** Known ransomware use: adds "ransomware". */
  ransomware?: boolean
}

/**
 * The one KEV (known exploited vulnerability) chip: a SignalChip preset with
 * the bolt in the danger colour. KEV is a supporting fact about the
 * vulnerability, so it never out-shouts the priority box. The text is always
 * present.
 */
export const KevBadge = React.forwardRef<HTMLSpanElement, KevBadgeProps>(function KevBadge(
  { label, pastDue, ransomware, ...props },
  ref
) {
  const { t } = useTranslation()
  return (
    <SignalChip
      ref={ref}
      slot="kev-badge"
      icon={Zap}
      tone="alert"
      alertText={pastDue}
      data-past-due={pastDue ? 'true' : undefined}
      data-ransomware={ransomware ? 'true' : undefined}
      {...props}
    >
      <span>{label ?? t('findings.list.kev', 'KEV')}</span>
      {ransomware && (
        <>
          {' '}
          <span>{t('findings.list.kevRansomware', 'ransomware')}</span>
        </>
      )}
      {pastDue && (
        <>
          {' '}
          <span>{t('findings.list.kevPastDue', 'past due')}</span>
        </>
      )}
    </SignalChip>
  )
})
