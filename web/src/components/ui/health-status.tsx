'use client'

import * as React from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { HEALTH_ICON_CLASS, HEALTH_TEXT_CLASS, type HealthState } from '@/lib/health-colors'
import { HealthGlyph } from '@/components/ui/health-glyphs'

interface HealthStatusBase {
  /** What a machine reports: ok, run, queued, warn, down, paused, off, unknown. */
  state: HealthState
  /**
   * The muted tail after the state ("42%", "4 s ago", "3 unreachable"). Several
   * parts render as separate spans with a gap, never joined by a glyph. The
   * tail is outside the state chip and wraps under it when the box is narrow.
   */
  detail?: string | string[]
  /** The raw domain value, written to `data-state` for tests and styling hooks. */
  value?: string
  /** Tooltip: what the state means. */
  title?: string
  className?: string
}

export type HealthStatusProps = HealthStatusBase &
  (
    | {
        iconOnly?: false
        /** The translated label. Defaults to the generic word of the state. */
        label?: React.ReactNode
      }
    | {
        /** Icon only, for dense matrices: the label becomes the tooltip and aria-label. */
        iconOnly: true
        label: string
      }
  )

/**
 * The state of a machine (sensor, run, job, integration, credential,
 * certificate): a filled-circle icon and plain text, no container. The icon
 * carries the colour and shape, the text stays in the foreground colour, so the
 * state reads without colour and passes AA. Nothing spins: a running state is
 * a static half circle.
 */
export function HealthStatus({
  state,
  label,
  detail,
  value,
  iconOnly,
  title,
  className,
}: HealthStatusProps) {
  const { t } = useTranslation()
  const text = label ?? t(`labels.health.${state}`, GENERIC_LABEL[state])
  const textString = typeof text === 'string' ? text : undefined
  const parts = (Array.isArray(detail) ? detail : detail ? [detail] : []).filter(Boolean)
  const full = [textString, ...parts].filter(Boolean).join(', ')
  const chip = (
    <span
      data-slot="health-status"
      data-health={state}
      data-state={value}
      title={title ?? (iconOnly ? full : undefined)}
      aria-label={iconOnly ? full : undefined}
      role={iconOnly ? 'img' : undefined}
      className={cn(
        'inline-flex w-fit max-w-full shrink-0 items-center gap-1.5 whitespace-nowrap text-xs font-medium',
        HEALTH_TEXT_CLASS[state],
        className
      )}
    >
      <HealthGlyph state={state} className={HEALTH_ICON_CLASS[state]} />
      {!iconOnly && (
        <span className="max-w-[200px] min-w-0 truncate" title={title ?? textString}>
          {text}
        </span>
      )}
    </span>
  )
  if (iconOnly || parts.length === 0) return chip
  // The detail sits beside the chip, not in it: the state stays one line, and
  // in a narrow box (a phone card column, a drawer) the detail drops under it
  // and wraps instead of running into the next column.
  return (
    <span
      data-slot="health-status-line"
      className="inline-flex max-w-full shrink-0 flex-wrap items-center gap-x-1.5 gap-y-0.5 text-xs"
    >
      {chip}
      {parts.map((part) => (
        <span key={part} className="min-w-0 break-words text-muted-foreground">
          {part}
        </span>
      ))}
    </span>
  )
}

const GENERIC_LABEL: Record<HealthState, string> = {
  ok: 'OK',
  run: 'Running',
  queued: 'Queued',
  warn: 'Needs attention',
  down: 'Down',
  paused: 'Paused',
  off: 'Off',
  unknown: 'Unknown',
}
