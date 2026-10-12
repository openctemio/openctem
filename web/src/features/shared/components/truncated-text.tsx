'use client'

/**
 * One line of an attacker-influenced string (research 20 §5): a target, host,
 * URL, tool name or a tool's error message.
 *
 * - React text only, never markup, never a link (a link goes through
 *   `safe-href.ts`, and the caller decides that, not this component).
 * - One line with an ellipsis; `dir="auto"` and `unicode-bidi: isolate`, so a
 *   right-to-left value cannot reorder the text around it.
 * - Control characters, line breaks and bidi overrides are shown as visible
 *   escapes (`toDisplayText`), and the value is capped, so it cannot fake a
 *   second row, hide text or freeze the page.
 * - The full (escaped) value is in a tooltip that opens on hover AND on
 *   keyboard focus, and is the accessible name, so it is not mouse-only like
 *   a `title` attribute.
 */

import * as React from 'react'
import { AlertTriangle } from 'lucide-react'

import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { hasHiddenCharacters, toDisplayText } from '@/lib/untrusted-text'

export interface TruncatedTextProps {
  value: string | null | undefined
  /** Shown when the value is empty. Default "-". */
  fallback?: React.ReactNode
  /** Classes for the visible line (width limits go here, e.g. `max-w-[260px]`). */
  className?: string
  /** What the value is, for screen readers ("Error message", "Target"). */
  label?: string
}

export function TruncatedText({ value, fallback = '-', className, label }: TruncatedTextProps) {
  const raw = value ?? ''
  if (raw.trim() === '') {
    return <span className={cn('text-muted-foreground', className)}>{fallback}</span>
  }
  const shown = toDisplayText(raw)
  const hidden = hasHiddenCharacters(raw)
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          dir="auto"
          data-slot="truncated-text"
          aria-label={label ? `${label}: ${shown}` : shown}
          className={cn(
            'block min-w-0 truncate rounded-sm [unicode-bidi:isolate] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
            className
          )}
        >
          {hidden && (
            <AlertTriangle
              className="me-1 inline h-3 w-3 align-[-2px] text-warning"
              aria-hidden="true"
            />
          )}
          {shown}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-[min(32rem,90vw)] whitespace-pre-wrap break-all text-start [unicode-bidi:isolate]">
        <span dir="auto">{shown}</span>
        {hidden && (
          <span className="mt-1 block opacity-80">
            Contains control or direction characters, shown as escapes.
          </span>
        )}
      </TooltipContent>
    </Tooltip>
  )
}
