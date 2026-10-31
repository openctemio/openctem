'use client'

import { ArrowRight, BrushCleaning } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * One line above the list when some sensors look abandoned: added over a day
 * ago and never connected, or offline for over a week (isCleanupCandidate).
 * The button narrows the list to them, where they can be selected and
 * deleted (or disabled) in one go; the same button shows every sensor again.
 * A hint line like the CI pipelines one, not a banner: nothing is wrong with
 * the page, it only saves the operator the hunt.
 */
export function SensorCleanupHint({
  count,
  active,
  onToggle,
  className,
}: {
  count: number
  active: boolean
  onToggle: () => void
  className?: string
}) {
  const { t } = useTranslation()
  if (count === 0 && !active) return null
  return (
    <p
      data-slot="sensor-cleanup-hint"
      className={cn(
        'flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted-foreground',
        className
      )}
    >
      <BrushCleaning className="h-4 w-4 shrink-0" aria-hidden />
      <span>
        {active
          ? t('sensors.cleanup.active')
          : t(count === 1 ? 'sensors.cleanup.hint.one' : 'sensors.cleanup.hint.other', undefined, {
              count,
            })}
      </span>
      <button
        type="button"
        onClick={onToggle}
        aria-pressed={active}
        className="inline-flex items-center gap-1 rounded-sm font-medium text-foreground hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {active ? t('sensors.cleanup.showAll') : t('sensors.cleanup.review')}
        {!active && <ArrowRight className="h-3.5 w-3.5" aria-hidden />}
      </button>
    </p>
  )
}
