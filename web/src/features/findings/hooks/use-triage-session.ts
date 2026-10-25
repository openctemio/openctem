'use client'

/**
 * Triage mode's queue state: the session (resumed from the tab's
 * sessionStorage when it is the same queue), the windows read through the
 * findings list API, and the moves (next, previous, decide, skip).
 * Design: research/234 §5.2. The pure rules live in lib/triage-session.
 */

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { fetchTriageWindow, type TriageWindow } from '../api/triage-api'
import {
  TRIAGE_LIST_PATH,
  TRIAGE_WINDOW,
  mergeWindow,
  moveTo,
  needsWindow,
  newSession,
  nextUndecided,
  readSession,
  setOutcome,
  writeSession,
  type TriageOutcome,
  type TriageSession,
} from '../lib/triage-session'

/** Pages one refill may read before it gives up (all of them already seen). */
const MAX_PAGES_PER_REFILL = 4

/** Outcomes after which a finding most likely still matches a "new" queue. */
const STILL_MATCHING: ReadonlySet<TriageOutcome> = new Set([
  'skipped',
  'assigned',
  'fp_requested',
  'accept_requested',
])

/**
 * The page to start a refill from. Decided findings left the view, so the
 * server's pages shift; starting a little before where the seen findings
 * that still match would end keeps the read short without skipping any.
 */
export function refillStartPage(s: TriageSession): number {
  let stillMatching = 0
  for (const it of s.items) {
    const o = s.outcomes[it.id]
    if (!o || STILL_MATCHING.has(o)) stillMatching++
  }
  return Math.max(1, Math.floor(stillMatching / TRIAGE_WINDOW))
}

export type TriageDirection = 'forward' | 'back'

/** `query` null: the URL is not settled yet, nothing is read. */
export function useTriageSession(query: string | null) {
  const [session, setSession] = useState<TriageSession | null>(null)
  const [loadError, setLoadError] = useState<unknown>(null)
  const [loadingWindow, setLoadingWindow] = useState(false)
  const loadingRef = useRef(false)
  const sessionRef = useRef<TriageSession | null>(null)
  // How the shown finding was reached: a finding someone else changed is
  // passed over on the way forward, and shown (with its note) on the way back.
  const direction = useRef<TriageDirection>('forward')

  useLayoutEffect(() => {
    sessionRef.current = session
  }, [session])
  useEffect(() => {
    if (session) writeSession(session)
  }, [session])

  const loadWindow = useCallback(async (from: TriageSession) => {
    if (loadingRef.current) return
    loadingRef.current = true
    setLoadingWindow(true)
    setLoadError(null)
    try {
      const windows: TriageWindow[] = []
      let probe = from
      let page = from.items.length === 0 ? 1 : refillStartPage(from)
      for (let i = 0; i < MAX_PAGES_PER_REFILL; i++, page++) {
        const w = await fetchTriageWindow(from.query, page)
        windows.push(w)
        const merged = mergeWindow(probe, w.items, w.total, w.lastPage)
        probe = merged.session
        if (merged.added > 0 || w.lastPage) break
      }
      const stalled = probe.items.length === from.items.length && !probe.exhausted
      setSession((prev) => {
        let next = prev && prev.query === from.query ? prev : from
        for (const w of windows) next = mergeWindow(next, w.items, w.total, w.lastPage).session
        // Every page read held only findings already seen: stop asking.
        if (stalled) next = { ...next, exhausted: true, total: next.items.length }
        return next
      })
    } catch (error) {
      setLoadError(error)
      setSession((prev) => prev ?? from)
    } finally {
      loadingRef.current = false
      setLoadingWindow(false)
    }
  }, [])

  // Start or resume the queue of this query.
  useEffect(() => {
    if (query === null) return
    const stored = readSession(query)
    if (stored && stored.items.length > 0) {
      setSession(stored)
      return
    }
    void loadWindow(stored ?? newSession(query, TRIAGE_LIST_PATH, false))
  }, [query, loadWindow])

  // Read the next window before the shown finding reaches the end of the loaded ones.
  useEffect(() => {
    if (session && !loadError && needsWindow(session)) void loadWindow(session)
  }, [session, loadError, loadWindow])

  const go = useCallback((index: number, dir: TriageDirection) => {
    direction.current = dir
    setSession((s) => (s ? moveTo(s, index) : s))
  }, [])

  // Functional updates: several keys pressed before a render each move once.
  const next = useCallback(() => {
    direction.current = 'forward'
    setSession((s) => (s && s.index < s.items.length ? moveTo(s, s.index + 1) : s))
  }, [])

  const prev = useCallback(() => {
    direction.current = 'back'
    setSession((s) => (s && s.index > 0 ? moveTo(s, s.index - 1) : s))
  }, [])

  /** Records what happened to a finding and moves on to the next undecided one. */
  const decide = useCallback((id: string, outcome: TriageOutcome) => {
    direction.current = 'forward'
    setSession((s) => {
      if (!s) return s
      const withOutcome = setOutcome(s, id, outcome)
      const from = withOutcome.items.findIndex((it) => it.id === id)
      const after = nextUndecided(withOutcome, from < 0 ? withOutcome.index : from)
      return moveTo(withOutcome, after < 0 ? withOutcome.items.length : after)
    })
  }, [])

  const retry = useCallback(() => {
    const s = sessionRef.current
    setLoadError(null)
    if (s) void loadWindow(s)
  }, [loadWindow])

  return {
    session,
    loadError,
    loadingWindow,
    direction,
    next,
    prev,
    go,
    decide,
    retry,
  }
}
