'use client'

/**
 * Which targets of a scan wait for their scan windows and until when, and
 * which never open (the trigger refuses those). Used by the New Scan
 * previews (WindowPreview) and the run detail (RunWindowWaits). Targets and
 * window names are rendered as text.
 */

import { CalendarClock, CircleAlert } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

import { blockingNames, waitsSummary } from '../lib/decision'
import { formatInZone } from '../lib/schedule'
import type { TargetWait } from '../types'

/** Targets listed before "and N more". */
export const LISTED_WAITS = 5

interface WindowWaitsProps {
  waitingCount?: number
  waiting?: TargetWait[]
  nextOpenAt?: string
  neverCount?: number
  never?: TargetWait[]
  className?: string
}

function TargetLines({ items, total }: { items: TargetWait[]; total: number }) {
  const { t } = useTranslation()
  const shown = items.slice(0, LISTED_WAITS)
  const more = total - shown.length
  return (
    <ul className="space-y-1 text-xs">
      {shown.map((w, i) => (
        <li key={`${w.target}-${i}`} className="break-words">
          <span className="font-mono">{w.target}</span>
          <span className="text-muted-foreground">
            {w.never
              ? ` · ${t('scanWindows.waits.neverOpens', 'never opens')}`
              : w.next_open_at
                ? ` · ${t('scanWindows.waits.opens', 'opens {at}', { at: formatInZone(w.next_open_at) })}`
                : ''}
            {(w.blocking?.length ?? 0) > 0 ? ` · ${blockingNames(w.blocking, t)}` : ''}
          </span>
        </li>
      ))}
      {more > 0 && (
        <li className="text-muted-foreground">
          {t('scanWindows.waits.more', 'and {n} more', { n: more })}
        </li>
      )}
    </ul>
  )
}

export function WindowWaits({
  waitingCount = 0,
  waiting = [],
  nextOpenAt,
  neverCount = 0,
  never = [],
  className,
}: WindowWaitsProps) {
  const { t } = useTranslation()
  // The never-opening targets are counted and listed on their own.
  const onlyWaiting = waiting.filter((w) => !w.never)
  const waitCount = waitingCount
  if (waitCount === 0 && neverCount === 0) return null
  return (
    <div className={cn('space-y-3', className)} data-testid="window-waits">
      {neverCount > 0 && (
        <div
          role="alert"
          className="space-y-1 rounded-md border border-destructive/50 p-3 text-sm text-destructive"
          data-testid="window-waits-never"
        >
          <p className="flex items-center gap-1.5 font-medium">
            <CircleAlert className="h-4 w-4 shrink-0" aria-hidden />
            {neverCount === 1
              ? t(
                  'scanWindows.waits.neverOne',
                  '1 target can never be scanned under its scan windows'
                )
              : t(
                  'scanWindows.waits.neverMany',
                  '{n} targets can never be scanned under their scan windows',
                  {
                    n: neverCount,
                  }
                )}
          </p>
          <p className="text-xs">
            {t(
              'scanWindows.waits.neverHint',
              'The scan will not start. Change the windows in Settings › Scan windows, or remove these targets.'
            )}
          </p>
          <TargetLines items={never} total={neverCount} />
        </div>
      )}
      {waitCount > 0 && (
        <div className="space-y-1 rounded-md border p-3 text-sm" data-testid="window-waits-waiting">
          <p className="flex items-center gap-1.5 font-medium">
            <CalendarClock className="h-4 w-4 shrink-0 text-warning" aria-hidden />
            {waitsSummary(
              { waiting_count: waitCount, waiting: onlyWaiting, next_open_at: nextOpenAt },
              t
            )}
          </p>
          <p className="text-xs text-muted-foreground">
            {t(
              'scanWindows.waits.hint',
              'The run starts now; these targets are scanned when their windows open.'
            )}
          </p>
          <TargetLines items={onlyWaiting} total={waitCount} />
        </div>
      )}
    </div>
  )
}
