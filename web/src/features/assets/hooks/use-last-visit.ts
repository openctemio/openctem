'use client'

/**
 * The viewer's previous visit to a page, per organization, for "New since
 * last visit" (research/124). It is a per-browser convenience kept in this
 * browser only. A visit is a page open more than 30 minutes after the last
 * one, so reopening the page during one session keeps the same "previous
 * visit". Storage may be unavailable (private mode, blocked site data); the
 * answer is then undefined and callers fall back to a fixed window.
 */

import { useEffect, useState } from 'react'

const PREFIX = 'openctem:visits:'
const SESSION_MS = 30 * 60 * 1000

interface Visits {
  /** The open that started the current session. */
  last: string
  /** The visit before it. */
  previous?: string
}

export function lastVisitKey(page: string, tenantId: string): string {
  return `${PREFIX}${page}:${tenantId}`
}

/** The visits after an open at `now` (pure, for tests). */
export function nextVisits(stored: Visits | null, now: Date): Visits {
  if (!stored || Number.isNaN(Date.parse(stored.last))) return { last: now.toISOString() }
  if (now.getTime() - Date.parse(stored.last) < SESSION_MS) return stored
  return { last: now.toISOString(), previous: stored.last }
}

export function useLastVisit(page: string, tenantId: string | undefined): string | undefined {
  const [previous, setPrevious] = useState<string | undefined>(undefined)
  useEffect(() => {
    if (!tenantId) return
    const key = lastVisitKey(page, tenantId)
    try {
      const raw = window.localStorage.getItem(key)
      const stored = raw ? (JSON.parse(raw) as Visits) : null
      const next = nextVisits(stored, new Date())
      window.localStorage.setItem(key, JSON.stringify(next))
      setPrevious(next.previous)
    } catch {
      // best-effort: storage unavailable or unreadable
    }
  }, [page, tenantId])
  return previous
}
