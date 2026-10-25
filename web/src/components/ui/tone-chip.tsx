import type * as React from 'react'
import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import { STATUS_TONE_CLASS } from '@/lib/status-colors'

/**
 * How much attention a label needs, in one colour language (research/266):
 * - `danger`: blocked or broken (deny list, HTTP 5xx);
 * - `caution`: look at it (public exposure, not in scope, held by a guardrail, 401/403);
 * - `ok`: as it should be (in scope, HTTP 2xx);
 * - `info`: neutral movement (HTTP 3xx);
 * - `neutral`: a set value with no alarm (restricted, excluded);
 * - `quiet`: little or nothing known (private, isolated, unknown).
 */
export type Tone = 'danger' | 'caution' | 'ok' | 'info' | 'neutral' | 'quiet'

/** Tint, text and edge per tone. Every text colour is AA on its tint and on the card. */
export const TONE_CLASS: Record<Tone, string> = {
  danger: 'bg-tone-danger-bg text-tone-danger-fg border-tone-danger-border',
  caution: STATUS_TONE_CLASS.accepted,
  ok: STATUS_TONE_CLASS.resolved,
  info: STATUS_TONE_CLASS.progress,
  neutral: STATUS_TONE_CLASS.open,
  quiet: 'bg-transparent text-muted-foreground border-border',
}

export interface ToneChipProps {
  tone: Tone
  /** The family's icon (globe for exposure, lock for a guardrail): shape, not colour, names the family. */
  icon?: LucideIcon
  label: React.ReactNode
  /** Tooltip: what the value means. */
  title?: string
  /** A dashed edge: the value is unknown or not set. */
  dashed?: boolean
  /** The raw value, written to `data-value` for tests and styling hooks. */
  value?: string
  className?: string
}

/**
 * A label a reader scans a column for: exposure, scope standing, HTTP status
 * class. The tint and the text carry the tone, the icon the family, and the
 * word is always there, so colour is never the only cue. One line, never
 * wider than 200px.
 */
export function ToneChip({
  tone,
  icon: Icon,
  label,
  title,
  dashed,
  value,
  className,
}: ToneChipProps) {
  return (
    <span
      data-slot="tone-chip"
      data-tone={tone}
      data-value={value}
      title={title}
      className={cn(
        'inline-flex h-[22px] w-fit max-w-[200px] shrink-0 items-center gap-1 whitespace-nowrap rounded-md border px-1.5 text-xs font-medium leading-none',
        TONE_CLASS[tone],
        dashed && 'border-dashed',
        className
      )}
    >
      {Icon && <Icon className="size-3 shrink-0" aria-hidden />}
      <span className="min-w-0 truncate">{label}</span>
    </span>
  )
}
