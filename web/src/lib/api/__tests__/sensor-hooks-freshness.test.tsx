import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook, waitFor } from '@testing-library/react'
import useSWR, { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const client = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('../client', async (orig) => ({ ...(await orig<object>()), ...client }))
const errors = vi.hoisted(() => ({ handleApiError: vi.fn() }))
vi.mock('../error-handler', async (orig) => ({
  ...(await orig<object>()),
  handleApiError: errors.handleApiError,
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't' } }) }))

import { invalidateSensorsCache, useAllSensors, useTenantSensorStats } from '../sensor-hooks'

afterEach(() => vi.clearAllMocks())

const fresh = ({ children }: { children: ReactNode }) => (
  <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
)

describe('polled sensor hooks', () => {
  it('never toast from a failed poll (the page shows an ErrorState)', async () => {
    client.get.mockRejectedValue(Object.assign(new Error('boom'), { statusCode: 400 }))
    renderHook(() => useAllSensors(), { wrapper: fresh })
    renderHook(() => useTenantSensorStats(), { wrapper: fresh })
    await waitFor(() => expect(client.get).toHaveBeenCalledTimes(2))
    // Let the rejections reach SWR's error handler.
    await new Promise((r) => setTimeout(r, 300))
    expect(errors.handleApiError).not.toHaveBeenCalled()
  })
})

describe('invalidateSensorsCache', () => {
  it('revalidates without clearing the data on screen', async () => {
    let release: (v: string) => void = () => {}
    let calls = 0
    const fetcher = () => {
      calls++
      return calls === 1 ? Promise.resolve('first') : new Promise<string>((r) => (release = r))
    }
    const { result } = renderHook(() => useSWR('/api/v1/sensors?freshness-test', fetcher))
    await waitFor(() => expect(result.current.data).toBe('first'))

    let pending: Promise<unknown> = Promise.resolve()
    act(() => {
      pending = invalidateSensorsCache()
    })
    await waitFor(() => expect(calls).toBe(2))
    // The second request is in flight: the old data must still be there.
    expect(result.current.data).toBe('first')
    await act(async () => {
      release('second')
      await pending
    })
    await waitFor(() => expect(result.current.data).toBe('second'))
  })
})
