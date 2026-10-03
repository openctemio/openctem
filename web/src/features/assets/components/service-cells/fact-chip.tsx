import * as React from 'react'
import { cn } from '@/lib/utils'

/**
 * The one chip every service cell is built from. Theme tokens only, so each
 * tone has its dark-mode value (ui-style-contract §6).
 *
 * - `neutral`: a recorded value (a technology, a label);
 * - `muted`: context (IP, CNAME, "+N");
 * - `success` / `info` / `warning` / `destructive`: a status with meaning;
 * - `unknown`: dashed, for a fact that was not collected. Never shown as a
 *   healthy value.
 */
export type FactChipTone =
  'neutral' | 'muted' | 'label' | 'success' | 'info' | 'warning' | 'destructive' | 'unknown'

const TONES: Record<FactChipTone, string> = {
  neutral: 'border-border bg-card text-foreground',
  muted: 'border-border bg-card text-muted-foreground',
  label: 'border-transparent bg-secondary text-secondary-foreground',
  success: 'border-transparent bg-success/15 text-success',
  info: 'border-transparent bg-info/15 text-info',
  warning: 'border-transparent bg-warning/15 text-warning',
  destructive: 'border-transparent bg-destructive/15 text-destructive',
  unknown: 'border-dashed border-border bg-transparent text-muted-foreground',
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

/** The explicit "we do not know" chip: "Unknown", "Not collected", … */
export function UnknownChip({
  children = 'Unknown',
  className,
  ...props
}: Omit<FactChipProps, 'tone'>) {
  return (
    <FactChip tone="unknown" className={className} {...props}>
      {children}
    </FactChip>
  )
}

/** A monospace run inside a chip, for identifiers (IPs, ports, hosts). */
export function ChipMono({ children }: { children: React.ReactNode }) {
  return <span className="min-w-0 truncate font-mono text-[11.5px]">{children}</span>
}

/** Chips laid out in a wrapping row. */
export function ChipRow({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('flex min-w-0 flex-wrap items-center gap-1', className)} {...props} />
}
