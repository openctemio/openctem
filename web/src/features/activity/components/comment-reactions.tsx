'use client'

/**
 * Reactions on a comment, pills under the body (emoji +
 * count, highlighted when you reacted, click to toggle, names on hover), a
 * trailing "+" pill, and the lazy emoji picker both of them open.
 */

import { useEffect, useState, type ReactNode } from 'react'
import dynamic from 'next/dynamic'
import { SmilePlus } from 'lucide-react'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import type { ActivityReaction } from '../types'
import {
  reactionAriaLabel,
  reactionTooltip,
  readFrequentEmoji,
  recordEmojiUse,
  type ReactionViewer,
} from '../lib/reactions'

const LazyEmojiPicker = dynamic(() => import('./emoji-picker'), {
  ssr: false,
  loading: () => (
    <div className="flex h-[22rem] w-[19rem] items-center justify-center text-sm text-muted-foreground">
      Loading…
    </div>
  ),
})

// ---------------------------------------------------------------------------
// ReactionPicker — the "+ add reaction" popover
// ---------------------------------------------------------------------------

export interface ReactionPickerProps {
  /** The button that opens the picker (rendered as the popover trigger). */
  children: ReactNode
  onSelect: (emoji: string) => void
  viewerId?: string
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

export function ReactionPicker({
  children,
  onSelect,
  viewerId,
  open: openProp,
  onOpenChange,
}: ReactionPickerProps) {
  const [openState, setOpenState] = useState(false)
  const open = openProp ?? openState
  const setOpen = (v: boolean) => {
    setOpenState(v)
    onOpenChange?.(v)
  }
  const [frequent, setFrequent] = useState<string[]>([])
  useEffect(() => {
    if (open) setFrequent(readFrequentEmoji(viewerId))
  }, [open, viewerId])

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>{children}</PopoverTrigger>
      <PopoverContent
        align="start"
        className="w-auto overflow-hidden p-0"
        // Keep Esc for the picker: it closes the popover, not the whole panel.
        onEscapeKeyDown={(e) => e.stopPropagation()}
      >
        {open && (
          <LazyEmojiPicker
            frequent={frequent}
            onSelect={(emoji) => {
              recordEmojiUse(emoji, viewerId)
              onSelect(emoji)
              setOpen(false)
            }}
          />
        )}
      </PopoverContent>
    </Popover>
  )
}

// ---------------------------------------------------------------------------
// ReactionPills — under a comment's body
// ---------------------------------------------------------------------------

export interface ReactionPillsProps {
  reactions: ActivityReaction[]
  viewer?: ReactionViewer
  /** Absent: read-only pills (no permission to react). */
  onToggle?: (emoji: string) => void
  /** Adds `emoji` (the picker): a no-op when the viewer already reacted with it. */
  onAdd?: (emoji: string) => void
  /** The emoji the viewer just added: it "pops" once (motion-safe only). */
  popped?: string | null
  className?: string
}

export function ReactionPills({
  reactions,
  viewer,
  onToggle,
  onAdd,
  popped,
  className,
}: ReactionPillsProps) {
  if (reactions.length === 0) return null

  return (
    <TooltipProvider delayDuration={300}>
      <div
        className={cn('flex flex-wrap items-center gap-1.5', className)}
        role="group"
        aria-label="Reactions"
      >
        {reactions.map((r) => {
          const label = reactionTooltip(r, viewer)
          const names = r.sampleUsers.map((u) => u.name)
          return (
            <Tooltip key={r.emoji}>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  aria-pressed={r.reactedByMe}
                  aria-label={reactionAriaLabel(r)}
                  disabled={!onToggle}
                  onClick={() => onToggle?.(r.emoji)}
                  className={cn(
                    'inline-flex h-6 items-center gap-1 rounded-full border px-2 text-xs transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:cursor-default',
                    r.reactedByMe
                      ? 'border-primary/50 bg-primary/10 text-foreground hover:bg-primary/15'
                      : 'bg-background text-muted-foreground hover:bg-accent hover:text-accent-foreground',
                    popped === r.emoji && 'motion-safe:animate-reaction-pop'
                  )}
                >
                  <span aria-hidden className="text-sm leading-none">
                    {r.emoji}
                  </span>
                  <span aria-hidden className="font-medium tabular-nums">
                    {r.count}
                  </span>
                </button>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-60">
                {names.length > 3 ? (
                  <div className="space-y-0.5">
                    <p className="font-medium">Reacted with {r.emoji}</p>
                    <ul className="text-xs">
                      {(r.reactedByMe ? ['You', ...names.filter((n) => n !== viewer?.name)] : names)
                        .slice(0, 5)
                        .map((n, i) => (
                          <li key={`${n}-${i}`}>{n}</li>
                        ))}
                    </ul>
                    {r.count > 5 && (
                      <p className="text-xs">
                        and {r.count - 5} other{r.count - 5 === 1 ? '' : 's'}
                      </p>
                    )}
                  </div>
                ) : (
                  label
                )}
              </TooltipContent>
            </Tooltip>
          )
        })}
        {onToggle && (
          <ReactionPicker onSelect={(e) => (onAdd ?? onToggle)(e)} viewerId={viewer?.id}>
            <button
              type="button"
              aria-label="Add reaction"
              title="Add reaction"
              className="inline-flex h-6 items-center rounded-full border border-dashed px-1.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            >
              <SmilePlus className="h-3.5 w-3.5" aria-hidden />
            </button>
          </ReactionPicker>
        )}
      </div>
    </TooltipProvider>
  )
}
