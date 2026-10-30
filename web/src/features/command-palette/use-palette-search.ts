'use client'

import { useEffect, useState } from 'react'
import {
  cveOf,
  paletteQuery,
  searchPalette,
  type PaletteEntity,
  type PaletteSearchAccess,
} from './palette-search'

/** Wait after the last keystroke before searching (one request per type). */
export const PALETTE_DEBOUNCE_MS = 250

export interface PaletteSearchState {
  results: PaletteEntity[]
  loading: boolean
  /** The whole query is a CVE id. */
  cve: string | null
}

/**
 * The palette's entity search: debounced, at least two characters, the
 * previous request aborted when the query changes, and only for the types
 * the caller may read. Results are kept in this hook only (no shared cache,
 * so nothing outlives the open palette or crosses accounts).
 */
export function usePaletteSearch(raw: string, access: PaletteSearchAccess): PaletteSearchState {
  const q = paletteQuery(raw)
  const [state, setState] = useState<{
    q: string | null
    results: PaletteEntity[]
    loading: boolean
  }>({
    q: null,
    results: [],
    loading: false,
  })
  const { findings, assets, tasks } = access
  useEffect(() => {
    if (!q || (!findings && !assets && !tasks)) {
      setState({ q: null, results: [], loading: false })
      return
    }
    setState((s) => ({ ...s, loading: true }))
    const ctrl = new AbortController()
    const timer = window.setTimeout(() => {
      searchPalette(q, { findings, assets, tasks }, ctrl.signal)
        .then((results) => {
          if (!ctrl.signal.aborted) setState({ q, results, loading: false })
        })
        .catch(() => {
          if (!ctrl.signal.aborted) setState({ q, results: [], loading: false })
        })
    }, PALETTE_DEBOUNCE_MS)
    return () => {
      window.clearTimeout(timer)
      ctrl.abort()
    }
  }, [q, findings, assets, tasks])
  return {
    results: state.q === q ? state.results : [],
    loading: state.loading,
    cve: cveOf(raw),
  }
}
