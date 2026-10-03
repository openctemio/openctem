/**
 * Turns an entity's activity into the rows the ActivityPanel draws: oldest
 * first, day separators, a "New since your last visit" divider, and runs of
 * system events folded into one row (GitHub's "hidden items").
 *
 * Pure and unit-tested (__tests__/activity-feed.test.ts); the panel only maps
 * rows to elements.
 */

import type { ActivityCommentItem, ActivityEventItem, ActivityFilter, ActivityItem } from '../types'

/** A run of this many consecutive events or more is folded into one row. */
export const COLLAPSE_RUN_MIN = 3

export type FeedRow =
  | { type: 'day'; key: string; date: Date }
  | { type: 'unread'; key: string }
  | { type: 'comment'; key: string; item: ActivityCommentItem }
  | { type: 'event'; key: string; item: ActivityEventItem }
  | {
      type: 'collapsed'
      /** Stable: the first event's id. Expanding is keyed by it. */
      key: string
      items: ActivityEventItem[]
      /** Distinct actor names, in order of first appearance. */
      actors: string[]
    }

function time(iso: string): number {
  const t = new Date(iso).getTime()
  return Number.isNaN(t) ? 0 : t
}

/** Oldest first; ties keep their input order (the API's). */
export function sortChronological<T extends ActivityItem>(items: readonly T[]): T[] {
  return items
    .map((item, i) => ({ item, i }))
    .sort((a, b) => time(a.item.at) - time(b.item.at) || a.i - b.i)
    .map((x) => x.item)
}

/** De-duplicates by id, keeping the first occurrence. */
export function uniqueById<T extends { id: string }>(items: readonly T[]): T[] {
  const seen = new Set<string>()
  const out: T[] = []
  for (const it of items) {
    if (seen.has(it.id)) continue
    seen.add(it.id)
    out.push(it)
  }
  return out
}

export function applyFilter(
  items: readonly ActivityItem[],
  filter: ActivityFilter
): ActivityItem[] {
  if (filter === 'comments') return items.filter((i) => i.kind === 'comment')
  if (filter === 'changes') return items.filter((i) => i.kind === 'event')
  return [...items]
}

/** The filter a panel opens on: Comments when there are any, else All. */
export function defaultFilter(items: readonly ActivityItem[]): ActivityFilter {
  return items.some((i) => i.kind === 'comment') ? 'comments' : 'all'
}

function dayKey(d: Date): string {
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`
}

/** Unread: newer than the last visit and not written by the viewer. */
export function isUnread(
  item: ActivityItem,
  lastSeenAt: number | null | undefined,
  viewerId?: string
): boolean {
  if (lastSeenAt == null) return false
  if (item.kind === 'comment' && item.pending) return false
  if (viewerId && item.actor.id === viewerId) return false
  return time(item.at) > lastSeenAt
}

export function countUnread(
  items: readonly ActivityItem[],
  lastSeenAt: number | null | undefined,
  viewerId?: string
): number {
  return items.filter((i) => isUnread(i, lastSeenAt, viewerId)).length
}

export interface BuildFeedOptions {
  filter: ActivityFilter
  /** Epoch ms of the viewer's previous visit; null on a first visit. */
  lastSeenAt?: number | null
  viewerId?: string
  /** Keys of folded runs the viewer has opened. */
  expanded?: ReadonlySet<string>
}

/**
 * The rows, oldest first. Runs of COLLAPSE_RUN_MIN+ events fold only in the
 * "all" view (in "changes" every row is an event, and folding them all would
 * hide the list), and a run never crosses a day separator or the unread
 * divider.
 */
export function buildFeedRows(items: readonly ActivityItem[], opts: BuildFeedOptions): FeedRow[] {
  const sorted = sortChronological(applyFilter(uniqueById(items), opts.filter))
  const rows: FeedRow[] = []
  const fold = opts.filter === 'all'
  let run: ActivityEventItem[] = []
  let lastDay = ''
  let unreadPlaced = false

  const flush = () => {
    if (run.length === 0) return
    const key = run[0].id
    if (fold && run.length >= COLLAPSE_RUN_MIN && !opts.expanded?.has(key)) {
      const actors: string[] = []
      for (const e of run) if (!actors.includes(e.actor.name)) actors.push(e.actor.name)
      rows.push({ type: 'collapsed', key, items: run, actors })
    } else {
      for (const e of run) rows.push({ type: 'event', key: e.id, item: e })
    }
    run = []
  }

  for (const item of sorted) {
    const d = new Date(item.at)
    const dk = Number.isNaN(d.getTime()) ? 'invalid' : dayKey(d)
    if (dk !== lastDay) {
      flush()
      rows.push({ type: 'day', key: `day-${dk}`, date: d })
      lastDay = dk
    }
    if (!unreadPlaced && isUnread(item, opts.lastSeenAt, opts.viewerId)) {
      flush()
      // Only worth a divider when something before it was already seen.
      if (rows.some((r) => r.type === 'comment' || r.type === 'event' || r.type === 'collapsed')) {
        rows.push({ type: 'unread', key: 'unread' })
      }
      unreadPlaced = true
    }
    if (item.kind === 'event') {
      run.push(item)
    } else {
      flush()
      rows.push({ type: 'comment', key: item.id, item })
    }
  }
  flush()
  return rows
}

/** "12 changes by System and 2 others". */
export function collapsedLabel(count: number, actors: readonly string[]): string {
  const who =
    actors.length === 0
      ? ''
      : actors.length === 1
        ? ` by ${actors[0]}`
        : ` by ${actors[0]} and ${actors.length - 1} other${actors.length - 1 === 1 ? '' : 's'}`
  return `${count} change${count === 1 ? '' : 's'}${who}`
}

/** "Today", "Yesterday", "May 10", or "May 10, 2025" for another year. */
export function dayLabel(date: Date, now: Date = new Date(), locale = 'en-US'): string {
  if (Number.isNaN(date.getTime())) return 'Unknown date'
  const startOf = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime()
  const diff = Math.round((startOf(now) - startOf(date)) / 86_400_000)
  if (diff === 0) return 'Today'
  if (diff === 1) return 'Yesterday'
  return date.toLocaleDateString(locale, {
    month: 'short',
    day: 'numeric',
    ...(date.getFullYear() !== now.getFullYear() ? { year: 'numeric' } : {}),
  })
}

/**
 * Plain text of a markdown comment for a one-line snippet: no markup, no
 * links' targets, collapsed whitespace. Never rendered as HTML.
 */
export function markdownSnippet(md: string, max = 140): string {
  const text = md
    .replace(/```[\s\S]*?```/g, ' [code] ')
    .replace(/`([^`]*)`/g, '$1')
    // Link targets may hold one level of parentheses: [x](javascript:f(1)).
    .replace(/!\[([^\]]*)\]\((?:[^()]|\([^()]*\))*\)/g, '$1')
    .replace(/\[([^\]]*)\]\((?:[^()]|\([^()]*\))*\)/g, '$1')
    .replace(/<[^>]*>/g, ' ')
    .replace(/^\s{0,3}(#{1,6}|>|[-*+]|\d+\.)\s+/gm, '')
    .replace(/[*_~]{1,3}([^*_~]+)[*_~]{1,3}/g, '$1')
    .replace(/\s+/g, ' ')
    .trim()
  if (text.length <= max) return text
  const cut = text.lastIndexOf(' ', max)
  return `${text.slice(0, cut > max * 0.6 ? cut : max)}…`
}
