import * as React from 'react'
import { cn } from '@/lib/utils'
import { TONE_CLASS } from '@/components/ui/tone-chip'

/**
 * The one chip every service cell is built from. Theme tokens only, so each
 * tone has its dark-mode value (ui-style-contract §6). The status tones are
 * the attention tones of ToneChip (all AA on their tint, research/266):
 * success is ok, info is info, warning is caution, destructive is danger.
 *
 * - `neutral`: a recorded value (a technology, a label);
 * - `muted`: context (IP, CNAME, "+N") and known negatives ("No TLS");
 * - `success` / `info` / `warning` / `destructive`: a status with meaning.
 *
 * There is no chip for a fact that was not collected. Lists render nothing
 * for it (an empty cell shows `EmptyCell`), and the drawer names it once in
 * `NotCollectedNote` (ui-style-contract §7, "Unknown facts").
 */
export type FactChipTone =
  'neutral' | 'muted' | 'label' | 'success' | 'info' | 'warning' | 'destructive'

const TONES: Record<FactChipTone, string> = {
  neutral: 'border-border bg-card text-foreground',
  muted: 'border-border bg-card text-muted-foreground',
  label: 'border-transparent bg-secondary text-secondary-foreground',
  // The attention tones of ToneChip (research/266): one colour language.
  success: TONE_CLASS.ok,
  info: TONE_CLASS.info,
  warning: TONE_CLASS.caution,
  destructive: TONE_CLASS.danger,
}

export const factChipBase =
  'inline-flex h-[22px] max-w-full shrink-0 items-center gap-1 whitespace-nowrap rounded-md border px-2 text-xs [&>svg]:size-3 [&>svg]:shrink-0'

export interface FactChipProps extends React.HTMLAttributes<HTMLSpanElement> {
  tone?: FactChipTone
}

export function FactChip({ tone = 'neutral', className, ...props }: FactChipProps) {
  return (
    <span
      data-slot="fact-chip"
      data-tone={tone}
      className={cn(factChipBase, TONES[tone], className)}
      {...props}
    />
  )
}

/** A monospace run inside a chip, for identifiers (IPs, ports, hosts). */
export function ChipMono({ children }: { children: React.ReactNode }) {
  return <span className="min-w-0 truncate font-mono text-xs">{children}</span>
}

/** Chips laid out in a wrapping row. */
export function ChipRow({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('flex min-w-0 flex-wrap items-center gap-1', className)} {...props} />
}
