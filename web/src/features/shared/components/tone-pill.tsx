'use client'

import type * as React from 'react'
import { cn } from '@/lib/utils'

/**
 * A state as a small tinted pill with a dot: the one look for a computed
 * state (a sensor's heartbeat state, a CI pipeline's status). Theme tokens
 * only (style contract §6); the label carries the meaning, never the colour
 * alone.
 */
export type PillTone = 'success' | 'warning' | 'destructive' | 'info' | 'muted'

export const PILL_TONE_CLASS: Record<PillTone, string> = {
  success: 'bg-success/15 text-success',
  warning: 'bg-warning/15 text-warning',
  destructive: 'bg-destructive/15 text-destructive',
  info: 'bg-info/15 text-info',
  muted: 'bg-muted text-muted-foreground',
}

export const PILL_DOT_CLASS: Record<PillTone, string> = {
  success: 'bg-success',
  warning: 'bg-warning',
  destructive: 'bg-destructive',
  info: 'bg-info',
  muted: 'bg-muted-foreground',
}

export interface TonePillProps {
  tone: PillTone
  label: React.ReactNode
  /** Tooltip: what the state means. */
  title?: string
  /** A muted line under the pill ("heartbeat 4s ago", "last run 3h ago"). */
  detail?: React.ReactNode
  /** Rendered as `data-state`, for tests and styling hooks. */
  state?: string
  className?: string
}

export function TonePill({ tone, label, title, detail, state, className }: TonePillProps) {
  const pill = (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium',
        PILL_TONE_CLASS[tone],
        !detail && className
      )}
      title={title}
      data-state={state}
    >
      <span aria-hidden className={cn('size-1.5 rounded-full', PILL_DOT_CLASS[tone])} />
      {label}
    </span>
  )
  if (!detail) return pill
  return (
    <span className={cn('inline-flex flex-col items-start gap-0.5', className)}>
      {pill}
      <span className="text-xs text-muted-foreground">{detail}</span>
    </span>
  )
}
