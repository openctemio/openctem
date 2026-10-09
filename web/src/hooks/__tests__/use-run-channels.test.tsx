/**
 * Run lists listen on the run:{id} channel of each live run (research/81):
 * a change notice refreshes the list, and while every live run is subscribed
 * the list stops fast polling. Polling stays the fallback when the socket is
 * down or a subscription is refused.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'

type Handler = (data: unknown) => void
const handlers = new Map<string, Handler>()
let refuse = false
const subscribe = vi.fn((channel: string, handler: Handler) => {
  if (refuse) return Promise.reject(new Error('forbidden'))
  handlers.set(channel, handler)
  return Promise.resolve()
})
const unsubscribe = vi.fn(() => Promise.resolve())
let connected = true

vi.mock('@/lib/websocket', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/websocket')>()
  return { ...actual, getWebSocketClient: () => ({ subscribe, unsubscribe }) }
})
vi.mock('@/context/websocket-provider', () => ({
  useWebSocket: () => ({ state: 'connected', isConnected: connected, reconnect: () => {} }),
}))

import { useRunChannels } from '../use-websocket'
import { runListRefreshInterval } from '@/features/scans/lib/run-display'

describe('useRunChannels', () => {
  beforeEach(() => {
    subscribe.mockClear()
    unsubscribe.mockClear()
    handlers.clear()
    refuse = false
    connected = true
  })

  it('subscribes to each live run and reports realtime once all are subscribed', async () => {
    const onChange = vi.fn()
    const { result } = renderHook(() => useRunChannels(['r2', 'r1', 'r1'], onChange))
    await waitFor(() => expect(result.current).toBe(true))
    expect(subscribe.mock.calls.map((c) => c[0]).sort()).toEqual(['run:r1', 'run:r2'])
    handlers.get('run:r1')?.({ type: 'run.changed', run_id: 'r1' })
    expect(onChange).toHaveBeenCalledTimes(1)
  })

  it('is not realtime while the socket is down', () => {
    connected = false
    const { result } = renderHook(() => useRunChannels(['r1'], () => {}))
    expect(result.current).toBe(false)
    expect(subscribe).not.toHaveBeenCalled()
  })

  it('is not realtime when a subscription is refused', async () => {
    refuse = true
    const { result } = renderHook(() => useRunChannels(['r1'], () => {}))
    await waitFor(() => expect(subscribe).toHaveBeenCalled())
    expect(result.current).toBe(false)
  })

  it('subscribes to nothing without live runs', () => {
    const { result } = renderHook(() => useRunChannels([], () => {}))
    expect(result.current).toBe(false)
    expect(subscribe).not.toHaveBeenCalled()
  })
})

describe('runListRefreshInterval', () => {
  const live = { data: [{ status: 'running' }] }
  const idle = { data: [{ status: 'completed' }] }
  it('polls fast only while a run is live and its notices cannot arrive', () => {
    expect(runListRefreshInterval(10_000, 120_000)(live)).toBe(10_000)
    expect(runListRefreshInterval(10_000, 120_000, true)(live)).toBe(120_000)
    expect(runListRefreshInterval(10_000, 120_000)(idle)).toBe(120_000)
  })
})
