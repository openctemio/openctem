'use client'

import { useEffect, useEffectEvent, useRef, useState } from 'react'
import { useSearchQuery } from '@/hooks/use-search-query'

/**
 * A search box whose settled value lives in the URL: the box keeps what the
 * person types, `useSearchQuery` settles it (debounce, minimum length), and
 * `commit` writes the settled term. A URL value written from elsewhere (clear
 * all, a saved view, back and forward) replaces the box.
 *
 * The URL value this box wrote itself is remembered, so its echo does not
 * reset the box: keys typed between the write and the echo stay. Resetting on
 * every URL change dropped them (typing "repo-1" with short pauses left
 * "reo1").
 */
export function useCommittedSearch(
  urlValue: string | undefined,
  commit: (term: string) => void
): [string, (value: string) => void] {
  const [input, setInput] = useState(urlValue ?? '')
  const term = useSearchQuery(input).term
  const written = useRef(urlValue ?? '')

  useEffect(() => {
    const fromUrl = urlValue ?? ''
    if (fromUrl === written.current) return
    written.current = fromUrl
    setInput(fromUrl)
  }, [urlValue])

  // Read as an effect event: only a newly settled term writes the URL.
  const write = useEffectEvent((next: string) => {
    if (next === (urlValue ?? '')) return
    written.current = next
    commit(next)
  })
  useEffect(() => {
    write(term)
  }, [term])

  return [input, setInput]
}
