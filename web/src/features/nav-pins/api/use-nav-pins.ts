'use client'

import { useCallback, useMemo } from 'react'
import useSWR from 'swr'
import { toast } from 'sonner'
import { get, put } from '@/lib/api/client'
import { useCurrentTenantId } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'

/** The caller's sidebar pins in the current organization. */
export const NAV_PINS_URL = '/api/v1/me/pins'

export type NavPinKind = 'page' | 'quick_view' | 'saved_view'

export interface NavPin {
  kind: NavPinKind
  ref: string
  /** Saved view name. */
  name?: string
  /** Quick view list query. */
  params?: string
  /** Quick or saved view count, in the caller's scope. */
  count?: number
}

export interface NavPinsResponse {
  data: NavPin[]
  max: number
  include_informational: boolean
}

export const samePin = (a: Pick<NavPin, 'kind' | 'ref'>, b: Pick<NavPin, 'kind' | 'ref'>) =>
  a.kind === b.kind && a.ref === b.ref

/** The list after pinning or unpinning one item (pure, unit-tested). */
export function togglePin(
  pins: Pick<NavPin, 'kind' | 'ref'>[],
  pin: Pick<NavPin, 'kind' | 'ref'>,
  max: number
): Pick<NavPin, 'kind' | 'ref'>[] | null {
  if (pins.some((p) => samePin(p, pin))) return pins.filter((p) => !samePin(p, pin))
  if (pins.length >= max) return null
  return [...pins, pin]
}

/**
 * The pins, read once a minute at most (the sidebar shows them on every
 * page), and a toggle that writes the new list. The server checks every pin
 * again; a refused write keeps the old list and says why.
 */
export function useNavPins() {
  const { t } = useTranslation()
  // Null outside an organization (and in tests without one): nothing to read.
  const key = useCurrentTenantId() ? NAV_PINS_URL : null
  const { data, mutate } = useSWR<NavPinsResponse>(key, get, {
    dedupingInterval: 60_000,
    revalidateOnFocus: false,
  })
  const pins = useMemo(() => data?.data ?? [], [data])
  const max = data?.max ?? 12

  const isPinned = useCallback(
    (pin: Pick<NavPin, 'kind' | 'ref'>) => pins.some((p) => samePin(p, pin)),
    [pins]
  )

  const toggle = useCallback(
    async (pin: Pick<NavPin, 'kind' | 'ref'>) => {
      const next = togglePin(pins, pin, max)
      if (!next) {
        toast.error(t('nav.pins.full', 'You can pin up to {max} items', { max }))
        return
      }
      try {
        const saved = await put<NavPinsResponse>(NAV_PINS_URL, {
          pins: next.map((p) => ({ kind: p.kind, ref: p.ref })),
        })
        await mutate(saved, { revalidate: false })
      } catch {
        toast.error(t('nav.pins.saveFailed', 'The pins could not be saved. Try again.'))
      }
    },
    [pins, max, mutate, t]
  )

  return { pins, max, includeInformational: data?.include_informational ?? false, isPinned, toggle }
}
