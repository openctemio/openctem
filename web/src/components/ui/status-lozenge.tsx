import { cn } from '@/lib/utils'
import { STATUS_TONE_CLASS, type StatusTone } from '@/lib/status-colors'
import type { StatusGlyph } from '@/components/ui/status-glyphs'

export interface StatusLozengeProps {
  /** Workflow category: triage, open, progress, resolved, accepted, closed. */
  tone: StatusTone
  /** A glyph component (status-glyphs or a lucide icon); decorative. */
  icon?: StatusGlyph
  /** The translated label, sentence case. */
  label: string
  /** The raw status value, for tests and styling hooks. */
  value?: string
  className?: string
}

/**
 * The one workflow-status label: a lozenge (radius 6) whose subtle tint shows
 * the status category, with a progression icon. No animation. Used for finding
 * status and, with the same tones, for exposure state. The text is always
 * present, so colour is never the only cue.
 */
export function StatusLozenge({ tone, icon: Icon, label, value, className }: StatusLozengeProps) {
  return (
    <span
      data-slot="status-lozenge"
      data-tone={tone}
      data-status={value}
      className={cn(
        'inline-flex w-fit shrink-0 items-center gap-1 whitespace-nowrap rounded-md border px-1.5 py-0.5 text-xs font-medium leading-none',
        STATUS_TONE_CLASS[tone],
        className
      )}
    >
      {Icon && <Icon className="size-3 shrink-0" />}
      {label}
    </span>
  )
}
