'use client'

/**
 * The compact "Activity · N comments" summary a page shows in place of a full
 * timeline: the latest comment (plain-text snippet) or the latest change, an
 * unread dot, and one click (or `C`) to open the ActivityPanel.
 */

import { forwardRef, useEffect } from 'react'
import { ChevronRight, MessageSquare } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import type { ActivityItem } from '../types'
import { markdownSnippet, sortChronological } from '../lib/activity-feed'
import { ActivityTime } from './activity-items'

export interface ActivityTriggerProps {
  items: ActivityItem[]
  /** Total events the API knows of (for "N events" when no comments). */
  total?: number
  /** Something new since the viewer's last visit. */
  unread?: number
  loading?: boolean
  onOpen: (opts?: { compose?: boolean }) => void
  /**
   * `C` (outside text fields, no modifier) opens the panel with the composer
   * focused. One trigger per page should take it.
   */
  shortcut?: boolean
  /** The panel is open: `C` does nothing then. */
  panelOpen?: boolean
  /** The line shown when there is nothing yet. */
  emptyText?: string
  /** Replaces "N comments" / "N events" (e.g. "Latest events" for a cursor feed). */
  headline?: string
  /** `card` (bordered, default) or `plain` inside a card that already frames it. */
  variant?: 'card' | 'plain'

  className?: string
}

function isTyping(t: EventTarget | null) {
  const el = t as HTMLElement | null
  if (!el) return false
  return (
    el.isContentEditable ||
    el.tagName === 'INPUT' ||
    el.tagName === 'TEXTAREA' ||
    el.tagName === 'SELECT' ||
    !!el.closest('[role="dialog"],[role="menu"],[role="listbox"]')
  )
}

export const ActivityTrigger = forwardRef<HTMLButtonElement, ActivityTriggerProps>(
  function ActivityTrigger(
    {
      items,
      total,
      unread = 0,
      loading,
      onOpen,
      shortcut,
      panelOpen,
      emptyText = 'Nothing yet.',
      variant = 'card',
      headline: headlineProp,
      className,
    },
    ref
  ) {
    useEffect(() => {
      if (!shortcut || panelOpen) return
      const onKey = (e: KeyboardEvent) => {
        if (e.key !== 'c' && e.key !== 'C') return
        if (e.metaKey || e.ctrlKey || e.altKey || e.shiftKey || e.defaultPrevented) return
        if (isTyping(e.target)) return
        e.preventDefault()
        onOpen({ compose: true })
      }
      document.addEventListener('keydown', onKey)
      return () => document.removeEventListener('keydown', onKey)
    }, [shortcut, panelOpen, onOpen])

    const sorted = sortChronological(items.filter((i) => !(i.kind === 'comment' && i.pending)))
    const comments = sorted.filter((i) => i.kind === 'comment')
    const latestComment = comments[comments.length - 1]
    const latest = sorted[sorted.length - 1]
    const eventCount = total ?? sorted.length
    const headline =
      headlineProp ??
      (comments.length > 0
        ? `${comments.length} comment${comments.length === 1 ? '' : 's'}`
        : `${eventCount} event${eventCount === 1 ? '' : 's'}`)

    // The snippet line: the latest comment, else the latest change.
    let preview: React.ReactNode = null
    let previewText = ''
    if (latestComment && latestComment.kind === 'comment') {
      previewText = `${latestComment.actor.name}: ${markdownSnippet(latestComment.body, 120)}`
      preview = (
        <>
          <span className="font-medium text-foreground">{latestComment.actor.name}</span>
          <span>: {markdownSnippet(latestComment.body, 120)}</span>
        </>
      )
    } else if (latest && latest.kind === 'event') {
      previewText = latest.actor.name
      preview = (
        <>
          {latest.actor.name && (
            <span className="font-medium text-foreground">{latest.actor.name} </span>
          )}
          <span>{latest.summary}</span>
        </>
      )
    }
    const previewAt = latestComment?.at ?? latest?.at

    return (
      <button
        ref={ref}
        type="button"
        onClick={() => onOpen()}
        aria-haspopup="dialog"
        aria-label={`Activity, ${headline}${unread > 0 ? `, ${unread} new` : ''}. ${previewText}`.trim()}
        aria-keyshortcuts={shortcut ? 'C' : undefined}
        className={cn(
          'group flex w-full items-start gap-3 rounded-lg text-start transition-colors hover:bg-accent/50 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
          variant === 'card' ? 'border bg-card p-3' : '-mx-2 p-2',
          className
        )}
        data-slot="activity-trigger"
      >
        <span
          aria-hidden
          className="relative mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground"
        >
          <MessageSquare className="h-4 w-4" />
          {unread > 0 && (
            <span className="absolute -top-0.5 -end-0.5 size-2.5 rounded-full bg-primary ring-2 ring-card" />
          )}
        </span>
        <span className="min-w-0 flex-1" aria-hidden>
          <span className="flex items-center gap-1.5 text-sm">
            <span className="font-semibold">Activity</span>
            <span className="text-muted-foreground">·</span>
            <span className="text-muted-foreground tabular-nums">{headline}</span>
            {unread > 0 && (
              <span className="rounded-full bg-primary/10 px-1.5 text-[11px] font-medium text-primary tabular-nums">
                {unread} new
              </span>
            )}
          </span>
          {loading && !latest ? (
            <Skeleton className="mt-1.5 h-4 w-2/3" />
          ) : preview ? (
            <span className="mt-0.5 flex min-w-0 items-baseline gap-2 text-sm text-muted-foreground">
              <span className="min-w-0 flex-1 truncate">{preview}</span>
              {previewAt && <ActivityTime at={previewAt} className="shrink-0" />}
            </span>
          ) : (
            <span className="mt-0.5 block text-sm text-muted-foreground">{emptyText}</span>
          )}
        </span>
        <ChevronRight
          aria-hidden
          className="mt-2 h-4 w-4 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5 rtl:rotate-180"
        />
      </button>
    )
  }
)
