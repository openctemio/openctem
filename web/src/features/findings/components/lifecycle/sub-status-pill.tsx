'use client'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { subStatusDotClass } from '@/lib/sub-status-colors'
import { subStatusName, type LifecycleSubStatus } from '../../api/use-finding-lifecycles'

interface SubStatusPillProps {
  subStatus: Pick<LifecycleSubStatus, 'name' | 'labels' | 'color' | 'canonical_status'>
  /** Also show the canonical status in muted text ("In review · In Progress"). */
  showStatus?: boolean
  className?: string
}

/**
 * An organization's sub-status: a dot in its palette colour and its name in
 * the reader's language. Organization names are plain text (React escapes
 * them). The canonical status, when shown, is muted: it is what metrics read.
 */
export function SubStatusPill({ subStatus, showStatus, className }: SubStatusPillProps) {
  const { t, locale } = useTranslation()
  return (
    <span
      className={cn(
        'inline-flex max-w-full items-center gap-1.5 whitespace-nowrap rounded-full border bg-muted/40 px-2 py-0.5 text-xs font-medium text-foreground',
        className
      )}
      data-sub-status
    >
      <span
        aria-hidden
        className={cn('size-1.5 shrink-0 rounded-full', subStatusDotClass(subStatus.color))}
      />
      <span className="truncate">{subStatusName(subStatus, locale)}</span>
      {showStatus && (
        <span className="text-muted-foreground">
          {'· '}
          {t(`findings.status.${subStatus.canonical_status}`, subStatus.canonical_status)}
        </span>
      )}
    </span>
  )
}
