'use client'

import { useCallback, useMemo } from 'react'
import useSWR from 'swr'
import { toast } from 'sonner'
import { get, put } from '@/lib/api/client'
import { useCurrentTenantId } from '@/context/tenant-provider'
import { useBootstrapPending } from '@/context/bootstrap-provider'
import { NAV_PINS_URL } from '@/context/bootstrap-session'
import { useTranslation } from '@/context/i18n-provider'

export { NAV_PINS_URL }

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

/** No refetch of a seeded or loaded value on mount, focus or reconnect. */
export const NAV_PINS_SWR_OPTIONS = {
  dedupingInterval: 60_000,
  revalidateOnFocus: false,
  revalidateOnReconnect: false,
  revalidateIfStale: false,
} as const

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
 * The pins and a toggle that writes the new list. The session bootstrap
 * carries the pins with their counts, so a page load sends no request for
 * them: the hook waits for the bootstrap and reads the seeded value without
 * revalidating it. Only when the bootstrap left them out (an older API, or a
 * failed read) does it ask GET /me/pins, once. The server checks every pin
 * again on write; a refused write keeps the old list and says why.
 */
export function useNavPins() {
  const { t } = useTranslation()
  // Null outside an organization (and in tests without one): nothing to read.
  // Null while the bootstrap is loading, so its seed is read instead.
  const bootstrapPending = useBootstrapPending()
  const key = useCurrentTenantId() && !bootstrapPending ? NAV_PINS_URL : null
  const { data, mutate } = useSWR<NavPinsResponse>(key, get, NAV_PINS_SWR_OPTIONS)
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
