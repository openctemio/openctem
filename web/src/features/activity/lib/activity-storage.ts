/**
 * Per-viewer browser state of an activity feed: when the viewer last saw it
 * (the "New since your last visit" divider and the unread dot) and the comment
 * they had started typing (the draft survives closing the panel).
 *
 * localStorage, keyed by user and entity. It is a convenience: a private
 * window, blocked storage or another device simply starts fresh, so every
 * read and write is guarded and the feed works without it. A server-side
 * read marker is the follow-up (web/docs/ui/activity-panel.md, "Phase B").
 */

const PREFIX = 'openctem:activity'

/** `entityKey` is "<kind>:<id>", e.g. "finding:3f2c…". */
export function storageKey(
  kind: 'seen' | 'draft',
  viewerId: string | undefined,
  entityKey: string
) {
  return `${PREFIX}:${kind}:${viewerId || 'anon'}:${entityKey}`
}

function read(key: string): string | null {
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null
  }
}

function write(key: string, value: string | null) {
  try {
    if (value === null) window.localStorage.removeItem(key)
    else window.localStorage.setItem(key, value)
  } catch {
    // Storage unavailable (private mode, quota): the feature degrades quietly.
  }
}

/** Epoch ms of the last visit, or null when never seen here. */
export function readLastSeen(viewerId: string | undefined, entityKey: string): number | null {
  const raw = read(storageKey('seen', viewerId, entityKey))
  if (raw === null || !/^\d+$/.test(raw)) return null
  return Number(raw)
}

export function writeLastSeen(viewerId: string | undefined, entityKey: string, at: number) {
  write(storageKey('seen', viewerId, entityKey), String(Math.floor(at)))
}

/** A draft is capped so a pasted log cannot fill the origin's quota. */
export const MAX_DRAFT_LENGTH = 10_000

export function readDraft(viewerId: string | undefined, entityKey: string): string {
  return read(storageKey('draft', viewerId, entityKey)) ?? ''
}

export function writeDraft(viewerId: string | undefined, entityKey: string, text: string) {
  write(
    storageKey('draft', viewerId, entityKey),
    text.trim() ? text.slice(0, MAX_DRAFT_LENGTH) : null
  )
}
