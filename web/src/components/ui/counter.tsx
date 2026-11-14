'use client'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export interface CounterProps {
  /** The number of things. */
  value: number
  /** Ink fill, only for a count of things waiting for the user. */
  emphasis?: boolean
  /** Above this the counter reads "99+". */
  max?: number
  /**
   * `badge`: 16 px, on the corner of a 32 px icon button (the header's
   * approvals and notifications). `default`: 18 px, inline after a label.
   */
  size?: 'default' | 'badge'
  className?: string
}

/**
 * A number: a nav count, a tab count, "+3". A small neutral round pill with
 * tabular digits. The ink emphasis is reserved for "waiting for you" counts, so
 * a plain count never shouts. The screen-reader name is the full number.
 */
export function Counter({ value, emphasis, max = 99, size = 'default', className }: CounterProps) {
  const { t } = useTranslation()
  if (!Number.isFinite(value)) return null
  const n = Math.max(0, Math.trunc(value))
  return (
    <span
      data-slot="counter"
      data-emphasis={emphasis ? 'true' : undefined}
      data-size={size}
      role="img"
      aria-label={t('labels.counter.aria', '{count} items', { count: n })}
      className={cn(
        'inline-flex shrink-0 items-center justify-center rounded-full font-semibold leading-none tabular-nums',
        size === 'badge' ? 'h-4 min-w-4 px-1 text-cap' : 'h-4.5 min-w-5 px-1.5 text-cap',
        emphasis ? 'bg-ctr-em-bg text-ctr-em-fg' : 'bg-ctr-bg text-ctr-fg',
        className
      )}
    >
      <span aria-hidden>{n > max ? `${max}+` : n}</span>
    </span>
  )
}
