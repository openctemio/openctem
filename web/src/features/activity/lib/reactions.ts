/**
 * Reactions on a comment: the optimistic toggle, the words for the tooltip and
 * the screen-reader label, and the viewer's frequently used emoji.
 */

import type { ActivityReaction } from '../types'

/** The quick reactions in a comment's action bar: triage acknowledgements. */
export const QUICK_REACTIONS = ['👍', '👀', '✅', '🎉'] as const

/** Same caps as the API, so the UI does not offer what the server refuses. */
export const MAX_DISTINCT_REACTIONS = 20
export const MAX_REACTIONS_PER_USER = 10

export interface ReactionViewer {
  id?: string
  name: string
}

/**
 * The list after the viewer toggles `emoji`. A new emoji goes last and an
 * existing one keeps its place, so pills never reshuffle (the API orders by
 * first use too). A pill whose count drops to zero disappears.
 */
export function toggleReaction(
  reactions: readonly ActivityReaction[],
  emoji: string,
  viewer: ReactionViewer
): ActivityReaction[] {
  const existing = reactions.find((r) => r.emoji === emoji)
  if (!existing) {
    return [...reactions, { emoji, count: 1, reactedByMe: true, sampleUsers: [viewer] }]
  }
  if (existing.reactedByMe) {
    return reactions
      .map((r) =>
        r.emoji !== emoji
          ? r
          : {
              ...r,
              count: r.count - 1,
              reactedByMe: false,
              sampleUsers: r.sampleUsers.filter((u) =>
                viewer.id ? u.id !== viewer.id : u.name !== viewer.name
              ),
            }
      )
      .filter((r) => r.count > 0)
  }
  return reactions.map((r) =>
    r.emoji !== emoji
      ? r
      : { ...r, count: r.count + 1, reactedByMe: true, sampleUsers: [...r.sampleUsers, viewer] }
  )
}

/** Whether the viewer may add `emoji` (caps); removing is always allowed. */
export function canAddReaction(reactions: readonly ActivityReaction[], emoji: string): boolean {
  const existing = reactions.find((r) => r.emoji === emoji)
  if (existing?.reactedByMe) return true
  if (!existing && reactions.length >= MAX_DISTINCT_REACTIONS) return false
  return reactions.filter((r) => r.reactedByMe).length < MAX_REACTIONS_PER_USER
}

function othersOf(r: ActivityReaction, viewer?: ReactionViewer) {
  return r.sampleUsers.filter((u) =>
    viewer?.id ? u.id !== viewer.id : viewer ? u.name !== viewer.name : true
  )
}

/** "You, Jamie and 3 others reacted with 👀". */
export function reactionTooltip(r: ActivityReaction, viewer?: ReactionViewer): string {
  const names = othersOf(r, viewer).map((u) => u.name)
  if (r.reactedByMe) names.unshift('You')
  const shown = names.slice(0, 3)
  const rest = Math.max(0, r.count - shown.length)
  let who: string
  if (shown.length === 0) who = `${r.count} ${r.count === 1 ? 'person' : 'people'}`
  else if (rest === 0)
    who = shown.length === 1 ? shown[0] : `${shown.slice(0, -1).join(', ')} and ${shown.at(-1)}`
  else who = `${shown.join(', ')} and ${rest} other${rest === 1 ? '' : 's'}`
  return `${who} reacted with ${r.emoji}`
}

/** The pill's accessible name: "👀 3 reactions, including you, toggle". */
export function reactionAriaLabel(r: ActivityReaction): string {
  return `${r.emoji} ${r.count} reaction${r.count === 1 ? '' : 's'}${
    r.reactedByMe ? ', including you' : ''
  }, toggle`
}

// ---------------------------------------------------------------------------
// Frequently used (per viewer, browser storage; a convenience only)
// ---------------------------------------------------------------------------

const FREQ_KEY = 'openctem:reactions:frequent'
const FREQ_MAX = 16

function freqKey(viewerId?: string) {
  return `${FREQ_KEY}:${viewerId || 'anon'}`
}

/** The viewer's most used emoji, most used first. */
export function readFrequentEmoji(viewerId?: string, limit = 8): string[] {
  try {
    const raw = window.localStorage.getItem(freqKey(viewerId))
    if (!raw) return []
    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object') return []
    return Object.entries(parsed as Record<string, unknown>)
      .filter((e): e is [string, number] => typeof e[1] === 'number' && e[0].length <= 32)
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([emoji]) => emoji)
  } catch {
    return []
  }
}

export function recordEmojiUse(emoji: string, viewerId?: string) {
  try {
    const key = freqKey(viewerId)
    const raw = window.localStorage.getItem(key)
    const counts: Record<string, number> = raw ? JSON.parse(raw) : {}
    counts[emoji] = (typeof counts[emoji] === 'number' ? counts[emoji] : 0) + 1
    const kept = Object.entries(counts)
      .filter((e) => typeof e[1] === 'number')
      .sort((a, b) => b[1] - a[1])
      .slice(0, FREQ_MAX)
    window.localStorage.setItem(key, JSON.stringify(Object.fromEntries(kept)))
  } catch {
    // Storage unavailable: the picker simply has no "frequently used" row.
  }
}
