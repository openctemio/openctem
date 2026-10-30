'use client'

import { useEffect, useState, useSyncExternalStore } from 'react'
import { rateLimitRemainingMs } from '@/lib/api/rate-limit-backoff'

/**
 * The one way a typed search reaches the API.
 *
 * Every search box, picker and filter-as-you-type input passes what the user
 * typed through this hook and puts only `term` into the request (an SWR key or
 * a data hook's params). That gives every input the same load profile:
 *
 * - debounce: the term changes once the user pauses (`delay`, 300 ms);
 * - minimum length: a term shorter than `minChars` (2) counts as empty, so
 *   one letter never runs a full-table match;
 * - normalisation: trimmed, inner whitespace collapsed, Unicode NFC (a
 *   Vietnamese word typed through different input methods is one cache key),
 *   lower-cased on request; equal terms share one SWR cache entry;
 * - IME composition: nothing is sent while a composition (Vietnamese Telex,
 *   CJK) is open anywhere on the page; the term follows its end;
 * - hidden tab: a term that settles while the page is hidden is sent when it
 *   becomes visible again;
 * - 429: after a rate-limited answer the term waits out the server's
 *   Retry-After (see `rate-limit-backoff.ts`).
 *
 * Stale answers cannot overwrite newer ones because the request is keyed by
 * `term` (SWR returns only the current key's data and keeps the previous data
 * on screen while the new key loads). Clearing the box applies at once.
 */

export const SEARCH_DEBOUNCE_MS = 300
export const SEARCH_MIN_CHARS = 2

export interface SearchQueryOptions {
  /** Pause before the term follows the input. */
  delay?: number
  /** Shorter terms count as empty. Use 1 for id, CVE or exact lookups. */
  minChars?: number
  /** Lower-case the term (only where the server matches case-insensitively). */
  lowercase?: boolean
}

export interface SearchQuery {
  /** What to send: normalised, settled, '' below `minChars`. */
  term: string
  /** The input has changed and the term has not caught up yet. */
  pending: boolean
}

/** Trim, collapse whitespace, NFC; lower-case when asked. */
export function normalizeSearch(value: string, lowercase = false): string {
  const out = value.normalize('NFC').replace(/\s+/g, ' ').trim()
  return lowercase ? out.toLowerCase() : out
}

function gate(value: string, minChars: number): string {
  return Array.from(value).length >= minChars ? value : ''
}

// IME composition state for the whole page. Composition events bubble, so one
// pair of document listeners serves every input without wiring each one.
let composing = false
const listeners = new Set<() => void>()
let attached = false

function setComposing(next: boolean) {
  if (composing === next) return
  composing = next
  listeners.forEach((l) => l())
}

function attach() {
  if (attached || typeof document === 'undefined') return
  attached = true
  document.addEventListener('compositionstart', () => setComposing(true), true)
  document.addEventListener('compositionend', () => setComposing(false), true)
  // A composition cut short by leaving the field never sends compositionend
  // in some browsers; leaving the field ends it.
  document.addEventListener('focusout', () => setComposing(false), true)
}

function subscribeComposition(listener: () => void) {
  attach()
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

const getComposing = () => composing
const getServerComposing = () => false

/** Test helper: forget composition state between tests. */
export function resetSearchComposition(): void {
  composing = false
}

export function useSearchQuery(input: string, options: SearchQueryOptions = {}): SearchQuery {
  const { delay = SEARCH_DEBOUNCE_MS, minChars = SEARCH_MIN_CHARS, lowercase = false } = options
  const target = gate(normalizeSearch(input, lowercase), minChars)
  // The first render uses the input as it is (a deep link with ?q= loads at once).
  const [term, setTerm] = useState(target)
  const isComposing = useSyncExternalStore(subscribeComposition, getComposing, getServerComposing)

  useEffect(() => {
    if (target === term || isComposing) return
    let timer: ReturnType<typeof setTimeout> | undefined
    let onVisible: (() => void) | undefined

    const fire = () => {
      const wait = rateLimitRemainingMs()
      if (wait > 0) {
        timer = setTimeout(fire, wait)
        return
      }
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
        onVisible = () => {
          if (document.visibilityState !== 'visible') return
          document.removeEventListener('visibilitychange', onVisible!)
          onVisible = undefined
          fire()
        }
        document.addEventListener('visibilitychange', onVisible)
        return
      }
      setTerm(target)
    }

    timer = setTimeout(fire, target === '' ? 0 : delay)
    return () => {
      if (timer) clearTimeout(timer)
      if (onVisible) document.removeEventListener('visibilitychange', onVisible)
    }
  }, [target, term, isComposing, delay])

  return { term, pending: target !== term }
}
