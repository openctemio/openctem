'use client'

import { useEffect, useMemo, useState } from 'react'
import { get } from '@/lib/api/client'
import type { ApiFindingListResponse } from '../api/finding-api.types'
import {
  listQuery,
  locate,
  mergePage,
  readListContext,
  writeListContext,
  type FindingListContext,
} from '../lib/list-context'

/** The list API URL of one page of a list context (page is 1-based). */
export function listPageUrl(query: string, page: number, perPage: number): string {
  const q = new URLSearchParams(listQuery(query))
  q.set('page', String(page))
  q.set('per_page', String(perPage))
  return `/api/v1/findings?${q.toString()}`
}

export interface FindingListNav {
  label: string
  returnPath: string
  /** 1-based position and the list's size. */
  position: number
  total: number
  prevHref?: string
  nextHref?: string
}

const findingHref = (id: string) => `/findings/${encodeURIComponent(id)}`

/**
 * The list context of the finding on the page, or null when it was not opened
 * from a findings list (or its list no longer holds it). At the edge of the
 * known ids it reads the neighbouring page once, through the list API.
 */
export function useFindingListNav(findingId: string | undefined): FindingListNav | null {
  const [ctx, setCtx] = useState<FindingListContext | null>(null)
  useEffect(() => {
    setCtx(readListContext())
  }, [findingId])

  const pos = useMemo(() => (ctx && findingId ? locate(ctx, findingId) : null), [ctx, findingId])

  const before = pos?.loadPage?.before
  const after = pos?.loadPage?.after
  useEffect(() => {
    if (!ctx || (!before && !after)) return
    let cancelled = false
    const pages = [before, after].filter((p): p is number => !!p)
    void (async () => {
      let next = ctx
      for (const page of pages) {
        try {
          const res = await get<ApiFindingListResponse>(listPageUrl(ctx.query, page, ctx.perPage))
          next = mergePage(
            next,
            page,
            (res?.data ?? []).map((f) => f.id),
            res?.total ?? next.total
          )
        } catch {
          // No neighbour this time: the button stays off, the page still works.
        }
      }
      if (cancelled || next === ctx) return
      writeListContext(next)
      setCtx(next)
    })()
    return () => {
      cancelled = true
    }
  }, [ctx, before, after])

  if (!ctx || !pos) return null
  return {
    label: ctx.label,
    returnPath: ctx.returnPath,
    position: pos.index + 1,
    total: ctx.total,
    prevHref: pos.prevId ? findingHref(pos.prevId) : undefined,
    nextHref: pos.nextId ? findingHref(pos.nextId) : undefined,
  }
}
