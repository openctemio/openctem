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
   * parts render as separate spans with a gap, never joined by a glyph.
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
  return (
    <span
      data-slot="health-status"
      data-health={state}
      data-state={value}
      title={title ?? (iconOnly ? full : undefined)}
      aria-label={iconOnly ? full : undefined}
      role={iconOnly ? 'img' : undefined}
      className={cn(
        'inline-flex w-fit shrink-0 items-center gap-1.5 whitespace-nowrap text-xs font-medium',
        HEALTH_TEXT_CLASS[state],
        className
      )}
    >
      <HealthGlyph state={state} className={HEALTH_ICON_CLASS[state]} />
      {!iconOnly && (
        <span className="max-w-[200px] truncate" title={title ?? textString}>
          {text}
        </span>
      )}
      {!iconOnly &&
        parts.map((part) => (
          <span key={part} className="font-normal text-muted-foreground">
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
