'use client'

/**
 * ActivityPanel: an entity's full activity and comments in a right-hand sheet
 * (a full-width bottom sheet on phones), opened from an `ActivityTrigger`.
 *
 * - Oldest at the top, the composer pinned at the bottom (chat / issue style).
 * - Opens on the first unread item ("New since your last visit"), or at the
 *   bottom when everything was seen.
 * - All · Comments · Changes; Comments when there are any.
 * - Runs of 3+ system events fold into one row.
 * - Live items never move what you are reading: scrolled up, a "N new" pill
 *   appears instead, and screen readers hear it (aria-live polite).
 * - Optimistic send with Retry; optimistic reactions with rollback.
 *
 * Built on the shared DetailSheet frame (docs/ui-style-contract.md §8).
 * Design and research: web/docs/ui/activity-panel.md.
 */

import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
  type RefObject,
} from 'react'
import { ArrowDown, History, Loader2, Wifi, WifiOff } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailHeader, DetailSheet } from '@/features/shared/components/detail-sheet-layout'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { getErrorMessage } from '@/lib/api/error-handler'
import { cn } from '@/lib/utils'
import type { ActivityCommentItem, ActivityFilter, ActivityItem, ActivityReaction } from '../types'
import { ACTIVITY_FILTERS } from '../types'
import { buildFeedRows, defaultFilter, sortChronological, uniqueById } from '../lib/activity-feed'
import { toggleReaction, type ReactionViewer } from '../lib/reactions'
import {
  CollapsedEventsRow,
  CommentCard,
  DaySeparator,
  EventRow,
  UnreadDivider,
} from './activity-items'
import { ActivityComposer, type ActivityComposerHandle } from './activity-composer'

/** Above this many rows, off-screen rows skip layout and paint. */
export const VIRTUALIZE_AFTER = 200
/** "At the bottom" within this many pixels. */
const BOTTOM_SLACK = 80

export type ActivityLiveStatus = 'connected' | 'connecting' | 'offline'

export interface ActivityPanelComposer {
  /** Post the comment. Throw (reject) to mark it "Not sent" with Retry. */
  onSend: (body: string, opts: { internal: boolean }) => Promise<void>
  allowInternal?: boolean
  placeholder?: string
}

export interface ActivityPanelProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** "<kind>:<id>": drafts and the last-visit marker are kept per entity. */
  entityKey: string
  /** What the activity is about, under the title (the finding's name, …). */
  subject?: string
  title?: string
  items: ActivityItem[]
  /** The API's total, when it knows one (shown in the header). */
  total?: number
  loading?: boolean
  error?: unknown
  onRetry?: () => void
  hasOlder?: boolean
  loadingOlder?: boolean
  onLoadOlder?: () => void
  /** Live-updates indicator; absent when the feed has no live channel. */
  live?: ActivityLiveStatus
  /** Absent: read only (no permission, or the entity takes no comments). */
  composer?: ActivityPanelComposer
  /** The viewer: own comments, "by you", reactions. */
  viewer?: ReactionViewer
  /** Edit / delete the viewer's own comments. */
  onEditComment?: (item: ActivityCommentItem, body: string) => Promise<void>
  onDeleteComment?: (item: ActivityCommentItem) => Promise<void>
  /**
   * Add or remove the viewer's reaction. Resolve with the comment's new
   * reactions (or nothing; a refetch will bring them); reject to roll back.
   */
  onToggleReaction?: (
    item: ActivityCommentItem,
    emoji: string,
    add: boolean
  ) => Promise<ActivityReaction[] | void>
  /** Epoch ms of the viewer's previous visit (the unread divider). */
  lastSeen?: number | null
  /** Called when the viewer has seen the feed (on open and on close). */
  onSeen?: () => void
  /** Open with the composer focused (the `C` shortcut). */
  focusComposer?: boolean
  /** Focus returns here on close (the trigger). */
  returnFocusRef?: RefObject<HTMLElement | null>
  /** Copy for the empty state. */
  emptyTitle?: string
  emptyDescription?: string
  /**
   * A feed with its own layout and filters (a sensor's operational log): it
   * replaces the built-in feed, filter and composer, inside the same frame.
   */
  customBody?: ReactNode
}

const FILTER_LABEL: Record<ActivityFilter, string> = {
  all: 'All',
  comments: 'Comments',
  changes: 'Changes',
}

interface PendingComment extends ActivityCommentItem {
  internal: boolean
}

function FeedSkeleton() {
  return (
    <div className="space-y-4" aria-hidden data-testid="activity-panel-skeleton">
      {[0, 1, 2].map((i) => (
        <div key={i} className="space-y-2 rounded-lg border p-3">
          <div className="flex items-center gap-2">
            <Skeleton className="size-6 rounded-full" />
            <Skeleton className="h-4 w-28" />
          </div>
          <Skeleton className="h-4 w-4/5" />
          <Skeleton className="h-4 w-2/3" />
        </div>
      ))}
    </div>
  )
}

export function ActivityPanel({
  open,
  onOpenChange,
  entityKey,
  subject,
  title = 'Activity',
  items,
  total,
  loading,
  error,
  onRetry,
  hasOlder,
  loadingOlder,
  onLoadOlder,
  live,
  composer,
  viewer,
  onEditComment,
  onDeleteComment,
  onToggleReaction,
  lastSeen,
  onSeen,
  focusComposer,
  returnFocusRef,
  emptyTitle = 'No activity yet',
  emptyDescription,
  customBody,
}: ActivityPanelProps) {
  const bodyRef = useRef<HTMLDivElement>(null)
  const composerRef = useRef<ActivityComposerHandle>(null)
  const filterRef = useRef<HTMLDivElement>(null)

  const [filter, setFilter] = useState<ActivityFilter | null>(null)
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set())
  const [pending, setPending] = useState<PendingComment[]>([])
  const [reactionOverrides, setReactionOverrides] = useState<Map<string, ActivityReaction[]>>(
    () => new Map()
  )
  const [popped, setPopped] = useState<{ id: string; emoji: string } | null>(null)
  // The pop animation timer is cleared on unmount so it never sets state on an
  // unmounted panel.
  const popTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(
    () => () => {
      if (popTimer.current) clearTimeout(popTimer.current)
    },
    []
  )
  const [newCount, setNewCount] = useState(0)
  const [announce, setAnnounce] = useState('')
  // The divider is fixed when the panel opens; marking "seen" while it is open
  // must not move it.
  const [dividerSince, setDividerSince] = useState<number | null>(null)
  const initialScrollDone = useRef(false)
  // A state, not a ref: the sheet mounts its content after `open` flips, and
  // the observer below must attach once the element exists.
  const [contentEl, setContentEl] = useState<HTMLDivElement | null>(null)
  // What the view holds on to until the reader scrolls: content keeps growing
  // after the first paint (markdown renders lazily), which would otherwise
  // leave the panel short of the bottom or of the unread divider.
  const stick = useRef<'bottom' | 'divider' | null>(null)

  // ---- open / close bookkeeping -------------------------------------------
  const wasOpen = useRef(false)
  // Read at the moment the panel opens or closes, not on every change.
  const lastSeenRef = useRef(lastSeen)
  const onSeenRef = useRef(onSeen)
  useEffect(() => {
    lastSeenRef.current = lastSeen
    onSeenRef.current = onSeen
  }, [lastSeen, onSeen])
  useEffect(() => {
    if (open && !wasOpen.current) {
      setDividerSince(lastSeenRef.current ?? null)
      initialScrollDone.current = false
      setNewCount(0)
      onSeenRef.current?.()
    }
    if (!open && wasOpen.current) {
      onSeenRef.current?.()
      setFilter(null)
      setExpanded(new Set())
    }
    wasOpen.current = open
  }, [open])

  // ---- the feed ------------------------------------------------------------
  const merged = useMemo(() => {
    const withReactions = items.map((it) => {
      if (it.kind !== 'comment') return it
      const key = it.commentId ?? it.id
      const override = reactionOverrides.get(key)
      return override ? { ...it, reactions: override } : it
    })
    return sortChronological(uniqueById([...withReactions, ...pending]))
  }, [items, pending, reactionOverrides])

  const effectiveFilter: ActivityFilter = filter ?? defaultFilter(merged)
  const rows = useMemo(
    () =>
      buildFeedRows(merged, {
        filter: effectiveFilter,
        lastSeenAt: dividerSince,
        viewerId: viewer?.id,
        expanded,
      }),
    [merged, effectiveFilter, dividerSince, viewer?.id, expanded]
  )
  const commentCount = merged.filter((i) => i.kind === 'comment' && !i.pending).length
  const virtualize = rows.length > VIRTUALIZE_AFTER

  // ---- scrolling -------------------------------------------------------------
  const isNearBottom = useCallback(() => {
    const el = bodyRef.current
    if (!el) return true
    return el.scrollHeight - el.scrollTop - el.clientHeight <= BOTTOM_SLACK
  }, [])

  const scrollToBottom = useCallback((smooth = false) => {
    const el = bodyRef.current
    if (!el) return
    el.scrollTo({ top: el.scrollHeight, behavior: smooth ? 'smooth' : 'auto' })
    setNewCount(0)
  }, [])

  // First paint with data: the first unread item, else the bottom.
  useLayoutEffect(() => {
    if (!open || initialScrollDone.current || loading) return
    const el = bodyRef.current
    if (!el) return
    if (merged.length === 0 && !error) return
    initialScrollDone.current = true
    const divider = el.querySelector<HTMLElement>('[data-activity-unread]')
    stick.current = divider ? 'divider' : 'bottom'
    applyStick()
  }, [open, loading, merged.length, error, rows])

  function applyStick() {
    const el = bodyRef.current
    if (!el) return
    if (stick.current === 'divider') {
      const divider = el.querySelector<HTMLElement>('[data-activity-unread]')
      if (divider) {
        el.scrollTop = Math.max(0, divider.offsetTop - 16)
        return
      }
    }
    if (stick.current === 'bottom' || prev.current.nearBottom) el.scrollTop = el.scrollHeight
  }

  // Hold the position while content grows; let go once the reader scrolls.
  useEffect(() => {
    const el = bodyRef.current
    const content = contentEl
    if (!el || !content) return
    const release = () => {
      stick.current = null
    }
    el.addEventListener('wheel', release, { passive: true })
    el.addEventListener('touchmove', release, { passive: true })
    el.addEventListener('keydown', release)
    el.addEventListener('pointerdown', release)
    let ro: ResizeObserver | undefined
    if (typeof ResizeObserver !== 'undefined') {
      ro = new ResizeObserver(() => {
        if (initialScrollDone.current) applyStick()
      })
      ro.observe(content)
    }
    return () => {
      el.removeEventListener('wheel', release)
      el.removeEventListener('touchmove', release)
      el.removeEventListener('keydown', release)
      el.removeEventListener('pointerdown', release)
      ro?.disconnect()
    }
  }, [contentEl])

  // Keep the reading position when older items are prepended, and decide what
  // to do with items appended at the end.
  const prev = useRef<{ oldest?: string; newest?: string; height: number; nearBottom: boolean }>({
    height: 0,
    nearBottom: true,
  })
  useLayoutEffect(() => {
    const el = bodyRef.current
    const oldest = merged[0]?.id
    const newest = merged[merged.length - 1]?.id
    const p = prev.current
    if (el && open && initialScrollDone.current) {
      if (p.oldest && oldest !== p.oldest && newest === p.newest) {
        // Older page arrived above: keep what is on screen where it was.
        el.scrollTop += el.scrollHeight - p.height
      } else if (p.newest && newest !== p.newest) {
        const startIdx = merged.findIndex((i) => i.id === p.newest)
        const added = startIdx >= 0 ? merged.slice(startIdx + 1) : []
        const mineOnly = added.length > 0 && added.every((i) => i.kind === 'comment' && i.pending)
        if (mineOnly || p.nearBottom) {
          el.scrollTop = el.scrollHeight
        } else if (added.length > 0) {
          setNewCount((n) => n + added.length)
        }
        const fromOthers = added.filter((i) => !(i.kind === 'comment' && i.pending)).length
        if (fromOthers > 0) {
          setAnnounce(`${fromOthers} new activity item${fromOthers === 1 ? '' : 's'}`)
        }
      }
    }
    prev.current = {
      oldest,
      newest,
      height: el?.scrollHeight ?? 0,
      nearBottom: el ? isNearBottom() : true,
    }
  }, [merged, open, isNearBottom])

  const onScroll = () => {
    prev.current.nearBottom = isNearBottom()
    if (prev.current.nearBottom && newCount > 0) setNewCount(0)
  }

  // ---- focus -----------------------------------------------------------------
  const hasComposer = !!composer && !customBody
  useEffect(() => {
    if (open && focusComposer && hasComposer) {
      const t = setTimeout(() => composerRef.current?.focus(), 50)
      return () => clearTimeout(t)
    }
  }, [open, focusComposer, hasComposer])

  // ---- sending -------------------------------------------------------------------
  const pendingSeq = useRef(0)
  const send = useCallback(
    async (p: PendingComment) => {
      if (!composer) return
      setPending((list) => [
        ...list.filter((x) => x.id !== p.id),
        { ...p, pending: 'sending' as const },
      ])
      try {
        await composer.onSend(p.body, { internal: p.internal })
        setPending((list) => list.filter((x) => x.id !== p.id))
      } catch (e) {
        setPending((list) =>
          list.map((x) => (x.id === p.id ? { ...x, pending: 'failed' as const } : x))
        )
        toast.error(getErrorMessage(e, 'Comment not sent'))
      }
    },
    [composer]
  )

  const onComposerSend = (body: string, opts: { internal: boolean }) => {
    pendingSeq.current += 1
    const p: PendingComment = {
      kind: 'comment',
      id: `pending-${pendingSeq.current}-${Date.now()}`,
      at: new Date().toISOString(),
      actor: { id: viewer?.id, name: viewer?.name ?? 'You', kind: 'user' },
      body,
      internal: opts.internal,
      pending: 'sending',
    }
    // Your own comment is shown even under the Changes filter.
    if (effectiveFilter === 'changes') setFilter('all')
    void send(p)
  }

  // ---- reactions -------------------------------------------------------------------
  const toggle = useCallback(
    async (item: ActivityCommentItem, emoji: string) => {
      if (!onToggleReaction || !viewer) return
      const key = item.commentId ?? item.id
      const before = item.reactions ?? []
      const add = !before.find((r) => r.emoji === emoji)?.reactedByMe
      const optimistic = toggleReaction(before, emoji, viewer)
      setReactionOverrides((m) => new Map(m).set(key, optimistic))
      if (add) {
        setPopped({ id: key, emoji })
        if (popTimer.current) clearTimeout(popTimer.current)
        popTimer.current = setTimeout(
          () => setPopped((p) => (p?.id === key && p.emoji === emoji ? null : p)),
          200
        )
      }
      try {
        const next = await onToggleReaction(item, emoji, add)
        if (next) setReactionOverrides((m) => new Map(m).set(key, next))
      } catch (e) {
        setReactionOverrides((m) => new Map(m).set(key, before))
        toast.error(getErrorMessage(e, 'Reaction not saved'))
      }
    },
    [onToggleReaction, viewer]
  )

  // Server data caught up (its reactions changed): drop the local overrides.
  const serverReactions = useMemo(
    () =>
      JSON.stringify(
        items.map((i) => (i.kind === 'comment' ? [i.commentId ?? i.id, i.reactions ?? []] : null))
      ),
    [items]
  )
  useEffect(() => {
    setReactionOverrides((m) => (m.size === 0 ? m : new Map()))
  }, [serverReactions])

  // ---- render -----------------------------------------------------------------
  const liveLabel = live === 'connected' ? 'Live' : live === 'connecting' ? 'Connecting' : 'Offline'

  const header = (
    <DetailHeader
      title={
        <span className="inline-flex items-baseline gap-1.5">
          {title}
          {!customBody && (
            <span className="text-sm font-normal text-muted-foreground tabular-nums">
              {total ?? merged.filter((i) => !(i.kind === 'comment' && i.pending)).length}
            </span>
          )}
        </span>
      }
      badges={
        live ? (
          <span
            className="inline-flex items-center gap-1 text-xs text-muted-foreground"
            title={live === 'connected' ? 'Live updates on' : 'Live updates off'}
          >
            {live === 'connected' ? (
              <Wifi className="h-3.5 w-3.5 text-success" aria-hidden />
            ) : (
              <WifiOff className="h-3.5 w-3.5" aria-hidden />
            )}
            {liveLabel}
          </span>
        ) : undefined
      }
      meta={[
        subject,
        customBody ? undefined : `${commentCount} comment${commentCount === 1 ? '' : 's'}`,
      ]}
      onClose={() => onOpenChange(false)}
    />
  )

  const filters = (
    <div
      ref={filterRef}
      role="radiogroup"
      aria-label="Show"
      className="mt-3 mb-3 inline-flex items-center gap-0.5 rounded-md border bg-muted/40 p-0.5 text-xs"
      onKeyDown={(e) => {
        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return
        e.preventDefault()
        const i = ACTIVITY_FILTERS.indexOf(effectiveFilter)
        const next =
          ACTIVITY_FILTERS[
            (i + (e.key === 'ArrowRight' ? 1 : -1) + ACTIVITY_FILTERS.length) %
              ACTIVITY_FILTERS.length
          ]
        setFilter(next)
        requestAnimationFrame(() =>
          filterRef.current?.querySelector<HTMLElement>(`[data-filter="${next}"]`)?.focus()
        )
      }}
    >
      {ACTIVITY_FILTERS.map((f) => {
        const on = effectiveFilter === f
        return (
          <button
            key={f}
            type="button"
            role="radio"
            aria-checked={on}
            tabIndex={on ? 0 : -1}
            data-filter={f}
            onClick={() => setFilter(f)}
            className={cn(
              'rounded px-3 py-1 font-medium transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
              on
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            {FILTER_LABEL[f]}
          </button>
        )
      })}
    </div>
  )

  let body
  if (error && merged.length === 0) {
    body = <ErrorState title="activity" error={error} onRetry={onRetry} />
  } else if (loading && merged.length === 0) {
    body = <FeedSkeleton />
  } else if (rows.length === 0) {
    body =
      merged.length > 0 ? (
        <EmptyState
          icon={History}
          title={effectiveFilter === 'comments' ? 'No comments yet' : 'No changes yet'}
          description="Try another view."
          card={false}
          className="py-10"
        />
      ) : (
        <EmptyState
          icon={History}
          title={emptyTitle}
          description={emptyDescription ?? (composer ? 'Start the discussion below.' : undefined)}
          card={false}
          className="py-10"
        />
      )
  } else {
    body = (
      <>
        {hasOlder && onLoadOlder && (
          <div className="mb-4 flex justify-center">
            <Button variant="outline" size="sm" onClick={onLoadOlder} disabled={loadingOlder}>
              {loadingOlder && <Loader2 className="h-4 w-4 animate-spin" />}
              Load older
            </Button>
          </div>
        )}
        <ol aria-label="Activity" className="space-y-3">
          {rows.map((row) => {
            const style = virtualize
              ? ({ contentVisibility: 'auto', containIntrinsicSize: 'auto 72px' } as const)
              : undefined
            if (row.type === 'day') {
              return (
                <li key={row.key} role="none" style={style} className="pt-1">
                  <DaySeparator date={row.date} />
                </li>
              )
            }
            if (row.type === 'unread') {
              return (
                <li key={row.key} role="none">
                  <UnreadDivider />
                </li>
              )
            }
            if (row.type === 'collapsed') {
              return (
                <li key={row.key} style={style}>
                  <CollapsedEventsRow
                    items={row.items}
                    actors={row.actors}
                    onExpand={() => setExpanded((s) => new Set(s).add(row.key))}
                  />
                </li>
              )
            }
            if (row.type === 'event') {
              return (
                <li key={row.key} style={style}>
                  <EventRow item={row.item} />
                </li>
              )
            }
            const item = row.item
            const key = item.commentId ?? item.id
            const mine = !!viewer?.id && item.actor.id === viewer.id
            const p = item.pending ? pending.find((x) => x.id === item.id) : undefined
            return (
              <li key={row.key} style={style} className="pt-2">
                <CommentCard
                  item={item}
                  viewer={viewer}
                  popped={popped?.id === key ? popped.emoji : null}
                  onToggleReaction={
                    onToggleReaction && viewer && !item.pending
                      ? (emoji) => void toggle(item, emoji)
                      : undefined
                  }
                  onEdit={
                    mine && onEditComment && !item.pending
                      ? (b) => onEditComment(item, b)
                      : undefined
                  }
                  onDelete={
                    mine && onDeleteComment && !item.pending
                      ? () => onDeleteComment(item)
                      : undefined
                  }
                  onRetry={p ? () => void send(p) : undefined}
                  onDiscard={
                    p ? () => setPending((list) => list.filter((x) => x.id !== p.id)) : undefined
                  }
                />
              </li>
            )
          })}
        </ol>
        {error ? (
          <div className="mt-4">
            <ErrorState title="activity" error={error} onRetry={onRetry} />
          </div>
        ) : null}
      </>
    )
  }

  return (
    <DetailSheet
      open={open}
      onOpenChange={onOpenChange}
      width="xl"
      header={header}
      tabs={customBody ? undefined : filters}
      bodyRef={bodyRef}
      bodyClassName="relative pb-4"
      initialFocus={() =>
        focusComposer && composer
          ? null
          : (filterRef.current?.querySelector<HTMLElement>('[aria-checked="true"]') ?? null)
      }
      returnFocus={returnFocusRef ? () => returnFocusRef.current : undefined}
      onBodyScroll={onScroll}
      footer={
        composer && !customBody ? (
          <ActivityComposer
            ref={composerRef}
            entityKey={entityKey}
            viewerId={viewer?.id}
            onSend={onComposerSend}
            allowInternal={composer.allowInternal}
            placeholder={composer.placeholder}
          />
        ) : undefined
      }
    >
      <div ref={setContentEl}>{customBody ?? body}</div>
      {!customBody && newCount > 0 && (
        // Sticks to the bottom of the scrolling feed while you read above.
        <div className="pointer-events-none sticky bottom-1 mt-2 flex justify-center">
          <Button
            size="sm"
            className="pointer-events-auto h-7 rounded-full shadow-md"
            onClick={() => scrollToBottom(true)}
          >
            {newCount} new
            <ArrowDown className="h-3.5 w-3.5" />
          </Button>
        </div>
      )}
      <p className="sr-only" aria-live="polite" role="status">
        {announce}
      </p>
    </DetailSheet>
  )
}
