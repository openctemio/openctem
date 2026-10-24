import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useState, type ReactNode } from 'react'
import useSWR, { SWRConfig } from 'swr'

import {
  normalizeSearch,
  resetSearchComposition,
  useSearchQuery,
  type SearchQueryOptions,
} from '../use-search-query'
import { useDebounce } from '../use-debounce'
import {
  noteRateLimited,
  parseRetryAfter,
  rateLimitRemainingMs,
  resetRateLimitBackoff,
} from '@/lib/api/rate-limit-backoff'

/** Types one character every `gap` ms, the way a fast typist does (~150 ms). */
function typeInto(set: (v: string) => void, text: string, gap = 150) {
  for (let i = 1; i <= text.length; i++) {
    act(() => set(text.slice(0, i)))
    act(() => vi.advanceTimersByTime(gap))
  }
}

function useHarness(options?: SearchQueryOptions) {
  const [input, setInput] = useState('')
  return { input, setInput, ...useSearchQuery(input, options) }
}

describe('normalizeSearch', () => {
  it('trims, collapses whitespace and composes Unicode', () => {
    expect(normalizeSearch('  web   server\t01 ')).toBe('web server 01')
    // "Việt" typed as decomposed marks is the same term as the composed form.
    expect(normalizeSearch('Việt')).toBe('Việt')
    expect(normalizeSearch('ACME', true)).toBe('acme')
    expect(normalizeSearch('ACME')).toBe('ACME')
  })
})

describe('useSearchQuery', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    resetRateLimitBackoff()
    resetSearchComposition()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('settles once after typing pauses', () => {
    const { result } = renderHook(() => useHarness())
    const terms = new Set<string>()
    for (let i = 1; i <= 10; i++) {
      act(() => result.current.setInput('webserver1'.slice(0, i)))
      act(() => vi.advanceTimersByTime(150))
      terms.add(result.current.term)
    }
    expect([...terms]).toEqual([''])
    expect(result.current.pending).toBe(true)
    act(() => vi.advanceTimersByTime(300))
    expect(result.current.term).toBe('webserver1')
    expect(result.current.pending).toBe(false)
  })

  it('treats a term shorter than minChars as empty', () => {
    const { result } = renderHook(() => useHarness())
    act(() => result.current.setInput('a'))
    act(() => vi.advanceTimersByTime(1000))
    expect(result.current.term).toBe('')
    expect(result.current.pending).toBe(false)

    const exact = renderHook(() => useHarness({ minChars: 1 }))
    act(() => exact.result.current.setInput('7'))
    act(() => vi.advanceTimersByTime(300))
    expect(exact.result.current.term).toBe('7')
  })

  it('applies a cleared box at once', () => {
    const { result } = renderHook(() => useHarness())
    act(() => result.current.setInput('acme'))
    act(() => vi.advanceTimersByTime(300))
    expect(result.current.term).toBe('acme')
    act(() => result.current.setInput(''))
    act(() => vi.advanceTimersByTime(0))
    expect(result.current.term).toBe('')
  })

  it('uses a deep-linked value on the first render', () => {
    const { result } = renderHook(() => useSearchQuery('  acme  '))
    expect(result.current.term).toBe('acme')
    expect(result.current.pending).toBe(false)
  })

  it('sends nothing while an IME composition is open', () => {
    const { result } = renderHook(() => useHarness())
    act(() => {
      document.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true }))
    })
    // Telex: "vieejt" composes to "việt" through intermediate states.
    typeInto(result.current.setInput, 'vieejt')
    act(() => vi.advanceTimersByTime(2000))
    expect(result.current.term).toBe('')
    act(() => {
      result.current.setInput('việt')
      document.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true }))
    })
    act(() => vi.advanceTimersByTime(300))
    expect(result.current.term).toBe('việt')
  })

  it('waits for the page to be visible again', () => {
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden')
    try {
      const { result } = renderHook(() => useHarness())
      act(() => result.current.setInput('acme'))
      act(() => vi.advanceTimersByTime(5000))
      expect(result.current.term).toBe('')
      visibility.mockReturnValue('visible')
      act(() => {
        document.dispatchEvent(new Event('visibilitychange'))
      })
      expect(result.current.term).toBe('acme')
    } finally {
      visibility.mockRestore()
    }
  })

  it('holds new terms until a 429 Retry-After has passed', () => {
    const { result } = renderHook(() => useHarness())
    noteRateLimited('3')
    act(() => result.current.setInput('acme'))
    act(() => vi.advanceTimersByTime(300))
    expect(result.current.term).toBe('')
    act(() => vi.advanceTimersByTime(2700))
    expect(result.current.term).toBe('acme')
  })
})

describe('rate-limit backoff', () => {
  beforeEach(() => resetRateLimitBackoff())

  it('parses seconds and HTTP dates, with a default and a cap', () => {
    const now = Date.parse('2026-10-24T00:00:00Z')
    expect(parseRetryAfter('5', now)).toBe(5000)
    expect(parseRetryAfter('Sat, 24 Oct 2026 00:00:10 GMT', now)).toBe(10_000)
    expect(parseRetryAfter(null, now)).toBe(2000)
    expect(parseRetryAfter('soon', now)).toBe(2000)
    expect(parseRetryAfter('86400', now)).toBe(60_000)
  })

  it('keeps the longest wait', () => {
    noteRateLimited('10', 0)
    noteRateLimited('1', 0)
    expect(rateLimitRemainingMs(0)).toBe(10_000)
    expect(rateLimitRemainingMs(10_000)).toBe(0)
  })
})

/**
 * Requests per typed query, measured through SWR with a mocked fetch: a
 * 10-character query typed at 150 ms per key.
 */
describe('requests per 10-character query', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    resetRateLimitBackoff()
    resetSearchComposition()
  })
  afterEach(() => vi.useRealTimers())

  const wrapper = ({ children }: { children: ReactNode }) => (
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 2000 }}>{children}</SWRConfig>
  )

  /** A search box whose term goes into an SWR key, as the call sites do. */
  function mountBox(useTerm: (input: string) => string) {
    const fetcher = vi.fn(async (url: string) => ({ url }))
    const { result } = renderHook(
      () => {
        const [input, setInput] = useState('')
        const term = useTerm(input)
        useSWR(term ? `/api/v1/assets?search=${encodeURIComponent(term)}` : null, fetcher)
        return setInput
      },
      { wrapper }
    )
    return { fetcher, set: (v: string) => result.current(v) }
  }

  function measure(useTerm: (input: string) => string) {
    const box = mountBox(useTerm)
    typeInto(box.set, 'webserver1')
    act(() => vi.advanceTimersByTime(1000))
    return box.fetcher.mock.calls.map((c) => c[0])
  }

  it('raw input state: one request per keystroke', () => {
    expect(measure((input) => input.trim())).toHaveLength(10)
  })

  it('useSearchQuery: one request for the settled term', () => {
    expect(measure((input) => useSearchQuery(input).term)).toEqual([
      '/api/v1/assets?search=webserver1',
    ])
  })

  it('useSearchQuery: a pause after one letter sends nothing', () => {
    const box = mountBox((input) => useSearchQuery(input).term)
    act(() => box.set('w'))
    act(() => vi.advanceTimersByTime(1000))
    expect(box.fetcher).not.toHaveBeenCalled()
  })

  it('useDebounce alone sends a one-letter search after a pause', () => {
    // The helper the call sites used before: no minimum length, no IME hold.
    const box = mountBox((input) => useDebounce(input.trim(), 300))
    act(() => box.set('w'))
    act(() => vi.advanceTimersByTime(400))
    expect(box.fetcher).toHaveBeenCalledWith('/api/v1/assets?search=w')
  })
})
