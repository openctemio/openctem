'use client'

import type { ReactNode } from 'react'
import { Lock, X } from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'

export interface RemovableFilterChipProps {
  /** The sentence the chip reads ("Severity is Critical"), already display-safe text. */
  text: string
  /** Removes the filter; absent on a locked chip. */
  onRemove?: () => void
  /** Accessible name of the remove button ("Remove filter Severity is Critical"). */
  removeLabel?: string
  /** The chip comes from something the user cannot edit here (a saved view): a lock, no remove. */
  locked?: boolean
  /** Why the chip is locked (tooltip and accessible name of the lock). */
  lockedHint?: string
  /** Extra content after the text (rarely needed). */
  children?: ReactNode
  'data-testid'?: string
}

/**
 * The one active-filter chip of the chips row under a list toolbar
 * (`FilterChipsRow`): the filter's sentence and a remove button, or a lock
 * when the filter is not editable here. Every list draws its chips with it,
 * so chips look and answer the keyboard the same on every page.
 */
export function RemovableFilterChip({
  text,
  onRemove,
  removeLabel,
  locked = false,
  lockedHint,
  children,
  'data-testid': testId = 'filter-chip',
}: RemovableFilterChipProps) {
  return (
    <span
      data-testid={testId}
      data-locked={locked ? 'true' : undefined}
      className={cn(
        'inline-flex max-w-full items-center gap-1 rounded-full border bg-muted/50 py-0.5 text-xs',
        locked || !onRemove ? 'ps-2 pe-2' : 'ps-2.5 pe-1'
      )}
    >
      {locked && lockedHint && (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="inline-flex" role="img" aria-label={lockedHint}>
              <Lock className="size-3 text-muted-foreground" aria-hidden />
            </span>
          </TooltipTrigger>
          <TooltipContent>{lockedHint}</TooltipContent>
        </Tooltip>
      )}
      <span dir="auto" className="min-w-0 truncate [unicode-bidi:isolate]" title={text}>
        {text}
      </span>
      {children}
      {!locked && onRemove && (
        <button
          type="button"
          onClick={onRemove}
          aria-label={removeLabel ?? text}
          className="inline-flex size-5 shrink-0 items-center justify-center rounded-full text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <X className="size-3" aria-hidden />
        </button>
      )}
    </span>
  )
}
