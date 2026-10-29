/**
 * Triage mode's queue (research/234 §5.2): the findings of one list query,
 * decided one at a time in the list's order.
 *
 * The queue is a query, never a set of rows the client chose: every window
 * of findings is read through the same list API as the findings page, so
 * the server applies the caller's tenant and data scope each time. What the
 * tab keeps in sessionStorage is the query, the ordered ids seen so far and
 * what happened to each, so a reload resumes where the person was.
 *
 * Everything here is pure (no React, no network) so the queue mechanics are
 * unit-tested on their own.
 */

import type { FindingStatus } from '../types'

/** Findings read per window (the list API page size triage asks for). */
export const TRIAGE_WINDOW = 25
/** The most findings one session keeps (a session is a sitting, not a backlog). */
export const TRIAGE_MAX_ITEMS = 500
/** The default queue: findings still to be decided, in priority order. */
export const TRIAGE_DEFAULT_QUERY = 'status=new'
/** Where Exit goes when the stored path is missing or not a findings list. */
export const TRIAGE_LIST_PATH = '/findings'

const STORAGE_KEY = 'openctem.findings.triage'
const ID_RE = /^[0-9a-f-]{8,64}$/i
const VIEW_KEY_RE = /^[a-z_]{1,40}$/
const PARAM_RE = /^[a-z][a-z0-9_]{0,63}$/
/** Params that page the list; triage pages it itself. */
const PAGING_PARAMS = new Set(['page', 'per_page', 'cursor'])

/** What the person did with a finding in this session. */
export type TriageOutcome =
  | 'confirmed'
  | 'fp_requested'
  | 'fp_applied'
  | 'accept_requested'
  | 'accept_applied'
  | 'assigned'
  | 'tasked'
  | 'retest_requested'
  | 'skipped'
  /** Someone else changed it after the queue loaded: passed over. */
  | 'changed'

const OUTCOMES: ReadonlySet<string> = new Set([
  'confirmed',
  'fp_requested',
  'fp_applied',
  'accept_requested',
  'accept_applied',
  'assigned',
  'tasked',
  'retest_requested',
  'skipped',
  'changed',
])

/** The most decisions Undo can walk back. */
export const TRIAGE_UNDO_DEPTH = 10

/**
 * What Undo needs to walk one decision back: the finding, what was done,
 * and what it was before. Undo always goes through the inverse request
 * (its own permission check on the server), never a client-side reset.
 */
export interface TriageUndo {
  id: string
  outcome: TriageOutcome
  /** The status before a status decision. */
  previousStatus?: FindingStatus
  /** The assignee before an assignment (null: nobody). */
  previousAssigneeId?: string | null
  /** The approval request a false positive or acceptance request created. */
  approvalId?: string
}

/** Outcomes that count as a decision in the progress line. */
const DECIDED: ReadonlySet<TriageOutcome> = new Set([
  'confirmed',
  'fp_applied',
  'accept_applied',
  'assigned',
  'tasked',
  'retest_requested',
])
/** Outcomes that wait for a second person. */
const SENT_FOR_APPROVAL: ReadonlySet<TriageOutcome> = new Set(['fp_requested', 'accept_requested'])

/** One finding of the queue, as the list window returned it. */
export interface TriageItem {
  id: string
  title: string
  status: FindingStatus
  priorityClass?: string
  rank?: number
  /** Where the finding is (host[:port], URL or file): FindingTitleCell's target line. */
  target?: string
  /** The version the window saw; a later version means someone changed it. */
  rowVersion?: number
}

export interface TriageSession {
  v: 1
  /** The list API query of the queue (no paging params). */
  query: string
  /** The findings list to return to on Exit: always a `/findings?…` path. */
  returnTo: string
  /** Whether the person came here from that list (Exit then goes back in history). */
  fromList: boolean
  /** The built-in view the queue is (its name in the top bar), when started from one. */
  viewKey?: string
  items: TriageItem[]
  /** The finding shown, an index into items. */
  index: number
  outcomes: Record<string, TriageOutcome>
  /** The last decisions, newest last, at most TRIAGE_UNDO_DEPTH. */
  undo: TriageUndo[]
  /** Findings in the queue as last counted by the server, plus those seen. */
  total: number
  /** No more findings to read from the server. */
  exhausted: boolean
}

/**
 * The list API query of a triage URL: the filter and sort params as they
 * are, without paging. Param names must look like the list contract's
 * (lower snake case); anything else is dropped rather than forwarded.
 * An empty queue query means the default queue.
 */
export function triageQuery(search: string | URLSearchParams): string {
  const src = typeof search === 'string' ? new URLSearchParams(search) : search
  const out = new URLSearchParams()
  for (const [k, v] of src.entries()) {
    if (PAGING_PARAMS.has(k) || !PARAM_RE.test(k) || v === '' || v.length > 2000) continue
    out.append(k, v)
  }
  const q = out.toString()
  return q || TRIAGE_DEFAULT_QUERY
}

/** The triage route for a queue query. */
export function triageHref(query: string): string {
  return `/findings/triage?${triageQuery(query)}`
}

/**
 * The path Exit may navigate to: only the findings list itself, with its
 * query. Anything else (another path, another origin, a protocol-relative
 * or scheme URL, backslashes, control characters) becomes the plain list,
 * so a crafted session or link can never turn Exit into an open redirect.
 */
export function safeReturnPath(raw: unknown): string {
  if (typeof raw !== 'string' || raw.length > 4000) return TRIAGE_LIST_PATH
  if (/[\\\u0000-\u001f\u007f]/.test(raw)) return TRIAGE_LIST_PATH
  if (raw !== TRIAGE_LIST_PATH && !raw.startsWith(`${TRIAGE_LIST_PATH}?`)) return TRIAGE_LIST_PATH
  try {
    const base = 'https://triage.invalid'
    const url = new URL(raw, base)
    if (url.origin !== base || url.pathname !== TRIAGE_LIST_PATH) return TRIAGE_LIST_PATH
    return `${url.pathname}${url.search}`
  } catch {
    return TRIAGE_LIST_PATH
  }
}

/** A new session for a query, before its first window. */
export function newSession(
  query: string,
  returnTo: string,
  fromList: boolean,
  viewKey?: string
): TriageSession {
  return {
    v: 1,
    query: triageQuery(query),
    returnTo: safeReturnPath(returnTo),
    fromList,
    ...(viewKey && VIEW_KEY_RE.test(viewKey) ? { viewKey } : {}),
    items: [],
    index: 0,
    outcomes: {},
    undo: [],
    total: 0,
    exhausted: false,
  }
}

function isItem(x: unknown): x is TriageItem {
  if (!x || typeof x !== 'object') return false
  const it = x as Record<string, unknown>
  return typeof it.id === 'string' && ID_RE.test(it.id) && typeof it.title === 'string'
}

function isUndo(x: unknown): x is TriageUndo {
  if (!x || typeof x !== 'object') return false
  const u = x as Record<string, unknown>
  return (
    typeof u.id === 'string' &&
    ID_RE.test(u.id) &&
    typeof u.outcome === 'string' &&
    OUTCOMES.has(u.outcome) &&
    (u.previousStatus === undefined ||
      (typeof u.previousStatus === 'string' && /^[a-z_]{1,32}$/.test(u.previousStatus))) &&
    (u.approvalId === undefined ||
      (typeof u.approvalId === 'string' && ID_RE.test(u.approvalId))) &&
    (u.previousAssigneeId === undefined ||
      u.previousAssigneeId === null ||
      (typeof u.previousAssigneeId === 'string' && ID_RE.test(u.previousAssigneeId)))
  )
}

/** Records a decision for Undo, keeping the newest TRIAGE_UNDO_DEPTH. */
export function pushUndo(s: TriageSession, entry: TriageUndo): TriageSession {
  return { ...s, undo: [...s.undo, entry].slice(-TRIAGE_UNDO_DEPTH) }
}

/** Takes the newest decision off the Undo stack. */
export function popUndo(s: TriageSession): { session: TriageSession; entry?: TriageUndo } {
  if (s.undo.length === 0) return { session: s }
  return { session: { ...s, undo: s.undo.slice(0, -1) }, entry: s.undo[s.undo.length - 1] }
}

/** Parses a stored session; anything malformed reads as no session. */
export function parseSession(raw: string | null): TriageSession | null {
  if (!raw) return null
  try {
    const s = JSON.parse(raw) as Partial<TriageSession>
    if (!s || s.v !== 1 || typeof s.query !== 'string' || !Array.isArray(s.items)) return null
    const items = s.items.filter(isItem).slice(0, TRIAGE_MAX_ITEMS)
    const outcomes: Record<string, TriageOutcome> = {}
    for (const [id, o] of Object.entries(s.outcomes ?? {})) {
      if (ID_RE.test(id) && typeof o === 'string' && OUTCOMES.has(o))
        outcomes[id] = o as TriageOutcome
    }
    const index = Number.isInteger(s.index) ? Math.min(Math.max(0, s.index!), items.length) : 0
    return {
      v: 1,
      query: triageQuery(s.query),
      returnTo: safeReturnPath(s.returnTo),
      fromList: s.fromList === true,
      ...(typeof s.viewKey === 'string' && VIEW_KEY_RE.test(s.viewKey)
        ? { viewKey: s.viewKey }
        : {}),
      items,
      index,
      outcomes,
      total: Number.isFinite(s.total) ? Math.max(items.length, s.total!) : items.length,
      exhausted: s.exhausted === true,
      undo: (Array.isArray(s.undo) ? s.undo : []).filter(isUndo).slice(-TRIAGE_UNDO_DEPTH),
    }
  } catch {
    return null
  }
}

type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>

function storage(): StorageLike | null {
  try {
    return typeof window === 'undefined' ? null : window.sessionStorage
  } catch {
    return null
  }
}

/** The tab's session for this query, or null (another queue, none, or no storage). */
export function readSession(
  query: string,
  store: StorageLike | null = storage()
): TriageSession | null {
  try {
    const s = parseSession(store?.getItem(STORAGE_KEY) ?? null)
    return s && s.query === triageQuery(query) ? s : null
  } catch {
    return null
  }
}

export function writeSession(s: TriageSession, store: StorageLike | null = storage()): void {
  try {
    store?.setItem(STORAGE_KEY, JSON.stringify(s))
  } catch {
    // Storage full or blocked: the session still works, it just does not survive a reload.
  }
}

export function clearSession(store: StorageLike | null = storage()): void {
  try {
    store?.removeItem(STORAGE_KEY)
  } catch {
    // ignore
  }
}

/**
 * The list writes where triage should return before it navigates: a fresh
 * session for the queue (any earlier session in the tab is replaced).
 */
export function startSession(
  query: string,
  returnTo: string,
  viewKey?: string,
  store: StorageLike | null = storage()
) {
  writeSession(newSession(query, returnTo, true, viewKey), store)
}

/**
 * Adds a window's findings to the queue in the server's order, skipping ids
 * already in it (a finding the person skipped is still in the view and comes
 * back in later windows). Returns how many were new.
 */
export function mergeWindow(
  s: TriageSession,
  rows: TriageItem[],
  serverTotal: number,
  lastPage: boolean
): { session: TriageSession; added: number } {
  const seen = new Set(s.items.map((i) => i.id))
  const fresh = rows.filter((r) => isItem(r) && !seen.has(r.id))
  const room = TRIAGE_MAX_ITEMS - s.items.length
  const added = fresh.slice(0, Math.max(0, room))
  const items = [...s.items, ...added]
  // The server counts what still matches; the seen findings that still match
  // are part of that count, so only the unseen remainder is added.
  const seenInWindow = rows.filter((r) => seen.has(r.id)).length
  const unseenLeft = Math.max(0, serverTotal - seenInWindow - added.length)
  const exhausted = lastPage || items.length >= TRIAGE_MAX_ITEMS
  return {
    session: {
      ...s,
      items,
      total: exhausted ? items.length : Math.max(items.length, items.length + unseenLeft),
      exhausted,
    },
    added: added.length,
  }
}

/** The next index after `from` that has no outcome yet, or -1 among the loaded items. */
export function nextUndecided(s: TriageSession, from: number = s.index): number {
  for (let i = from + 1; i < s.items.length; i++) {
    if (!s.outcomes[s.items[i].id]) return i
  }
  return -1
}

/** Whether the queue should read its next window: near the end of what is loaded. */
export function needsWindow(s: TriageSession, lookahead = 5): boolean {
  return !s.exhausted && s.items.length - s.index <= lookahead
}

export function setOutcome(
  s: TriageSession,
  id: string,
  outcome: TriageOutcome | null
): TriageSession {
  const outcomes = { ...s.outcomes }
  if (outcome) outcomes[id] = outcome
  else delete outcomes[id]
  return { ...s, outcomes }
}

export function moveTo(s: TriageSession, index: number): TriageSession {
  return { ...s, index: Math.min(Math.max(0, index), s.items.length) }
}

export interface TriageProgress {
  /** 1-based position of the finding shown (0 when the queue is done). */
  position: number
  total: number
  decided: number
  sentForApproval: number
  skipped: number
  changed: number
}

export function progress(s: TriageSession): TriageProgress {
  let decided = 0
  let sentForApproval = 0
  let skipped = 0
  let changed = 0
  for (const o of Object.values(s.outcomes)) {
    if (DECIDED.has(o)) decided++
    else if (SENT_FOR_APPROVAL.has(o)) sentForApproval++
    else if (o === 'skipped') skipped++
    else if (o === 'changed') changed++
  }
  return {
    position: s.index < s.items.length ? s.index + 1 : 0,
    total: Math.max(s.total, s.items.length),
    decided,
    sentForApproval,
    skipped,
    changed,
  }
}

/**
 * Whether a finding changed after the queue loaded and the person did not
 * change it: a newer version with another status. Shown with a note and
 * passed over instead of decided on stale facts.
 */
export function changedElsewhere(
  item: TriageItem,
  current: { status: FindingStatus; row_version?: number },
  outcome: TriageOutcome | undefined
): boolean {
  if (outcome && outcome !== 'changed') return false
  if (current.status === item.status) return false
  if (item.rowVersion !== undefined && current.row_version !== undefined) {
    return current.row_version > item.rowVersion
  }
  return true
}
