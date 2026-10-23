'use client'

import type * as React from 'react'
import { cn } from '@/lib/utils'
import { HealthStatus } from '@/components/ui/health-status'
import type { HealthState } from '@/lib/health-colors'

/**
 * A computed state (a sensor's heartbeat state, a CI pipeline's status): the
 * shared HealthStatus label, an icon and plain text. The tone picks the state:
 * success is ok, warning needs attention, destructive is down, info is in
 * motion, muted is off. The text stays in the foreground colour, so every
 * tone passes AA, and the icon shape differs per tone, so colour is never the
 * only cue. A domain with a finer vocabulary (queued, paused, unknown) renders
 * HealthStatus directly.
 */
export type PillTone = 'success' | 'warning' | 'destructive' | 'info' | 'muted'

/** The health state each tone renders as. */
export const PILL_TONE_STATE: Record<PillTone, HealthState> = {
  success: 'ok',
  warning: 'warn',
  destructive: 'down',
  info: 'run',
  muted: 'off',
}

export interface TonePillProps {
  tone: PillTone
  label: React.ReactNode
  /** Tooltip: what the state means. */
  title?: string
  /** A muted line under the label ("heartbeat 4s ago", "last run 3h ago"). */
  detail?: React.ReactNode
  /** Rendered as `data-state`, for tests and styling hooks. */
  state?: string
  className?: string
}

export function TonePill({ tone, label, title, detail, state, className }: TonePillProps) {
  const status = (
    <HealthStatus
      state={PILL_TONE_STATE[tone]}
      label={label}
      title={title}
      value={state}
      className={!detail ? className : undefined}
    />
  )
  if (!detail) return status
  return (
    <span className={cn('inline-flex flex-col items-start gap-0.5', className)}>
      {status}
      <span className="text-xs text-muted-foreground">{detail}</span>
    </span>
  )
}
