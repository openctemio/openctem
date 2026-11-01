import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import useSWR, { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const client = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('../client', async (orig) => ({ ...(await orig<object>()), ...client }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't' } }) }))

import { useNow } from '@/hooks/use-now'
import {
  EXPECTATION_POLL_MS,
  expectationRefreshInterval,
  usePairingExpectation,
  type SensorPairingView,
} from '../sensor-pairing-hooks'

const fresh = ({ children }: { children: ReactNode }) => (
  <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
)

const waiting = { id: 'p1', status: 'expecting', mode: 'reverse' } as SensorPairingView

/** Advance fake time in small steps so SWR's promises settle between ticks. */
async function advance(ms: number) {
  for (let t = 0; t < ms; t += 250) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(250)
    })
  }
}

/** The Add sensor panel: the hook plus a 1 s countdown that re-renders. */
function usePanel(id: string | null) {
  useNow(1000)
  // Read the fields during render, as the panel does (SWR re-renders only
  // for the fields a render read).
  const { data, error, isValidating, mutate } = usePairingExpectation(id)
  return { data, error, isValidating, mutate }
}

beforeEach(() => {
  vi.useFakeTimers()
  client.get.mockReset()
})
afterEach(() => vi.useRealTimers())

describe('usePairingExpectation polling', () => {
  it('polls every 3 s while the page re-renders every second (the prod bug)', async () => {
    client.get.mockResolvedValue(waiting)
    renderHook(() => usePanel('p1'), { wrapper: fresh })
    await advance(250)
    expect(client.get).toHaveBeenCalledTimes(1)
    await advance(3 * EXPECTATION_POLL_MS)
    expect(client.get.mock.calls.length).toBeGreaterThanOrEqual(4)
  })

  it('stops once the sensor revealed its nonce (SAS known)', async () => {
    client.get
      .mockResolvedValueOnce(waiting)
      .mockResolvedValue({ ...waiting, status: 'pending', sas: '12345' })
    const { result } = renderHook(() => usePanel('p1'), { wrapper: fresh })
    await advance(EXPECTATION_POLL_MS + 500)
    expect(result.current.data?.sas).toBe('12345')
    const calls = client.get.mock.calls.length
    await advance(4 * EXPECTATION_POLL_MS)
    expect(client.get).toHaveBeenCalledTimes(calls)
  })

  it('stops once the request settled', async () => {
    client.get.mockResolvedValue({ ...waiting, status: 'expired' })
    renderHook(() => usePanel('p1'), { wrapper: fresh })
    // The timer armed at mount (no data yet) may fire once; then none.
    await advance(EXPECTATION_POLL_MS + 500)
    const calls = client.get.mock.calls.length
    expect(calls).toBeLessThanOrEqual(2)
    await advance(4 * EXPECTATION_POLL_MS)
    expect(client.get).toHaveBeenCalledTimes(calls)
  })

  it('stops when the dialog closes', async () => {
    client.get.mockResolvedValue(waiting)
    const { unmount } = renderHook(() => usePanel('p1'), { wrapper: fresh })
    await advance(EXPECTATION_POLL_MS + 500)
    const calls = client.get.mock.calls.length
    unmount()
    await advance(4 * EXPECTATION_POLL_MS)
    expect(client.get).toHaveBeenCalledTimes(calls)
  })

  it('stops when the key goes away (approved)', async () => {
    client.get.mockResolvedValue(waiting)
    const { rerender } = renderHook(({ id }: { id: string | null }) => usePanel(id), {
      wrapper: fresh,
      initialProps: { id: 'p1' as string | null },
    })
    await advance(500)
    rerender({ id: null })
    await advance(4 * EXPECTATION_POLL_MS)
    expect(client.get).toHaveBeenCalledTimes(1)
  })

  it('does not retry a failed poll on its own; Check now (mutate) resumes polling', async () => {
    client.get.mockRejectedValueOnce(Object.assign(new Error('slow down'), { statusCode: 429 }))
    client.get.mockResolvedValue(waiting)
    const { result } = renderHook(() => usePanel('p1'), { wrapper: fresh })
    await advance(500)
    expect(result.current.error).toBeTruthy()
    await advance(4 * EXPECTATION_POLL_MS)
    expect(client.get).toHaveBeenCalledTimes(1)

    await act(async () => {
      await result.current.mutate()
    })
    expect(result.current.error).toBeFalsy()
    expect(client.get).toHaveBeenCalledTimes(2)
    await advance(2 * EXPECTATION_POLL_MS + 500)
    expect(client.get.mock.calls.length).toBeGreaterThanOrEqual(4)
  })

  it('the interval function has a stable identity and the right answers', () => {
    expect(expectationRefreshInterval(undefined)).toBe(EXPECTATION_POLL_MS)
    expect(expectationRefreshInterval(waiting)).toBe(EXPECTATION_POLL_MS)
    expect(expectationRefreshInterval({ ...waiting, sas: '1' })).toBe(0)
    expect(expectationRefreshInterval({ ...waiting, status: 'approved' })).toBe(0)
  })
})

describe('SWR refreshInterval identity (why the interval lives at module scope)', () => {
  it('an inline interval re-created every render never fires under a 1 s re-render', async () => {
    const fetcher = vi.fn().mockResolvedValue({})
    renderHook(
      () => {
        useNow(1000)
        return useSWR('/inline-interval', fetcher, { refreshInterval: () => 3000 })
      },
      { wrapper: fresh }
    )
    await advance(12000)
    expect(fetcher).toHaveBeenCalledTimes(1)
  })
})
