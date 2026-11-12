'use client'

/**
 * The typed entries that are not targets, each with its own reason (a range
 * too wide says how many addresses it has and the most one target holds),
 * and a one-click split for a range that fits in a few ranges of the widest
 * accepted size. Shared by the Targets step and the paste list. Format only:
 * scope is the API's answer. Design: research/418.
 */

import { Scissors } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { splitCidr, targetReasonText, type ClassifiedTarget } from '../../lib/target-format'

/** How many entries are named one by one; the rest are counted. */
export const LISTED_INVALID = 3

/** The one-click split of a range too wide for one target, or nothing. */
export function SplitRangeButton({
  entry,
  onSplit,
}: {
  entry: ClassifiedTarget
  onSplit: (entry: ClassifiedTarget, pieces: string[]) => void
}) {
  const { t } = useTranslation()
  if (!entry.split) return null
  const { bits, count } = entry.split
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className="h-7 shrink-0 gap-1 px-2 text-xs max-sm:h-9"
      onClick={() => onSplit(entry, splitCidr(entry.value, bits))}
    >
      <Scissors className="h-3.5 w-3.5" aria-hidden />
      {t('scans.targetReason.splitInto', undefined, {
        count: count.toLocaleString(),
        prefix: `/${bits}`,
      })}
    </Button>
  )
}

export function InvalidTargetsNote({
  entries,
  onSplit,
}: {
  entries: readonly ClassifiedTarget[]
  onSplit: (entry: ClassifiedTarget, pieces: string[]) => void
}) {
  const { t } = useTranslation()
  if (entries.length === 0) return null
  const listed = entries.slice(0, LISTED_INVALID)
  const more = entries.length - listed.length
  return (
    <div role="alert" className="space-y-1 text-xs text-destructive" data-testid="invalid-targets">
      <ul className="space-y-1">
        {listed.map((entry, i) => (
          <li key={`${i}:${entry.input}`} className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="min-w-0 break-words">
              <span className="font-mono">{entry.input}</span>
              {': '}
              {targetReasonText(t, entry)}
            </span>
            <SplitRangeButton entry={entry} onSplit={onSplit} />
          </li>
        ))}
      </ul>
      {more > 0 && (
        <p>
          {t(
            more === 1 ? 'scans.summary.invalidMoreOne' : 'scans.summary.invalidMoreMany',
            undefined,
            {
              count: more,
            }
          )}
        </p>
      )}
    </div>
  )
}
