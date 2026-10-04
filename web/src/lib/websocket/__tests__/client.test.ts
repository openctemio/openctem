import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/lib/logger', () => ({
  devLog: { log: vi.fn(), warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}))

import { devLog } from '@/lib/logger'
import { WebSocketClient, fullJitterDelay } from '../client'
import { WS_CLOSE } from '../types'

// A controllable stand-in for the browser WebSocket.
class FakeSocket {
  static CONNECTING = 0
  static OPEN = 1
  static CLOSING = 2
  static CLOSED = 3
  static instances: FakeSocket[] = []

  readyState = FakeSocket.CONNECTING
  sent: string[] = []
  onopen: (() => void) | null = null
  onclose: ((e: { code: number; reason: string }) => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((e: { data: string }) => void) | null = null

  constructor(
    public url: string,
    public protocols?: string | string[]
  ) {
    FakeSocket.instances.push(this)
  }

  send(data: string) {
    this.sent.push(data)
  }

  close() {
    this.readyState = FakeSocket.CLOSED
  }

  // test helpers
  open() {
    this.readyState = FakeSocket.OPEN
    this.onopen?.()
  }

  serverClose(code: number, reason = '') {
    this.readyState = FakeSocket.CLOSED
    this.onclose?.({ code, reason })
  }

  /** The handshake was refused (the browser reports 1006, no status). */
  refuse() {
    this.readyState = FakeSocket.CLOSED
    this.onerror?.()
    this.onclose?.({ code: 1006, reason: '' })
  }
}

const latest = () => FakeSocket.instances[FakeSocket.instances.length - 1]

describe('WebSocketClient (RFC-045)', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.clearAllMocks()
    FakeSocket.instances = []
    vi.stubGlobal('WebSocket', FakeSocket)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('opens the socket with no credential in the URL and no subprotocol token', () => {
    const client = new WebSocketClient({ url: 'wss://ctem.example.com/api/v1/ws' })
    client.connect()
    expect(latest().url).toBe('wss://ctem.example.com/api/v1/ws')
    expect(latest().protocols).toBeUndefined()
    client.disconnect()
  })

  it('full jitter stays within [0, min(cap, base*2^n))', () => {
    expect(fullJitterDelay(0, 1000, 30000, () => 0)).toBe(0)
    expect(fullJitterDelay(0, 1000, 30000, () => 0.999)).toBe(999)
    expect(fullJitterDelay(3, 1000, 30000, () => 0.5)).toBe(4000)
    expect(fullJitterDelay(10, 1000, 30000, () => 0.999)).toBe(29970)
  })

  it('on 4401 reconnects after a short jitter without refreshing when the cookie is still good', async () => {
    const onAuthExpired = vi.fn(async () => true)
    const client = new WebSocketClient({
      url: 'ws://x/api/v1/ws',
      onAuthExpired,
      random: () => 0.5,
      authReconnectJitterMs: 3000,
    })
    client.connect()
    latest().open()
    latest().serverClose(WS_CLOSE.UNAUTHORIZED, 'session expired')

    expect(client.getState()).toBe('reconnecting')
    await vi.advanceTimersByTimeAsync(1499)
    expect(FakeSocket.instances).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(FakeSocket.instances).toHaveLength(2)

    latest().open()
    expect(client.getState()).toBe('connected')
    expect(onAuthExpired).not.toHaveBeenCalled()
    client.disconnect()
  })

  it('refreshes the session once when the reconnect after 4401 is refused, then reconnects', async () => {
    const onAuthExpired = vi.fn(async () => true)
    const client = new WebSocketClient({ url: 'ws://x/api/v1/ws', onAuthExpired, random: () => 0 })
    client.connect()
    latest().open()
    latest().serverClose(WS_CLOSE.UNAUTHORIZED, 'session expired')
    await vi.advanceTimersByTimeAsync(0)
    expect(FakeSocket.instances).toHaveLength(2)

    latest().refuse() // cookie expired: handshake refused
    await vi.waitFor(() => expect(onAuthExpired).toHaveBeenCalledTimes(1))
    await vi.waitFor(() => expect(FakeSocket.instances).toHaveLength(3))

    // A second refusal does not refresh again; it falls back to backoff.
    latest().refuse()
    await vi.advanceTimersByTimeAsync(0)
    expect(onAuthExpired).toHaveBeenCalledTimes(1)
    expect(client.getState()).toBe('reconnecting')
    client.disconnect()
  })

  it('stops reconnecting when the session cannot be refreshed', async () => {
    const onAuthExpired = vi.fn(async () => false)
    const states: string[] = []
    const client = new WebSocketClient({
      url: 'ws://x/api/v1/ws',
      onAuthExpired,
      random: () => 0,
      onStateChange: (s) => states.push(s),
    })
    client.connect()
    latest().open()
    latest().serverClose(WS_CLOSE.UNAUTHORIZED, 'session revoked')
    await vi.advanceTimersByTimeAsync(0)
    latest().refuse()
    await vi.waitFor(() => expect(client.getState()).toBe('error'))

    await vi.advanceTimersByTimeAsync(120_000)
    expect(FakeSocket.instances).toHaveLength(2)
    expect(devLog.error).not.toHaveBeenCalled()
  })

  it('backs off for at least half the cap after 4429', async () => {
    const client = new WebSocketClient({
      url: 'ws://x/api/v1/ws',
      random: () => 0,
      maxReconnectDelay: 30000,
    })
    client.connect()
    latest().open()
    latest().serverClose(WS_CLOSE.TOO_MANY_CONNECTIONS, 'too many connections')
    await vi.advanceTimersByTimeAsync(14_999)
    expect(FakeSocket.instances).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(FakeSocket.instances).toHaveLength(2)
    client.disconnect()
  })

  it('does not reconnect after a normal close', async () => {
    const client = new WebSocketClient({ url: 'ws://x/api/v1/ws' })
    client.connect()
    latest().open()
    latest().serverClose(WS_CLOSE.NORMAL)
    await vi.advanceTimersByTimeAsync(60_000)
    expect(FakeSocket.instances).toHaveLength(1)
    expect(client.getState()).toBe('disconnected')
  })

  it('resets the backoff only after the connection stayed up', async () => {
    const delays: number[] = []
    const client = new WebSocketClient({
      url: 'ws://x/api/v1/ws',
      random: () => 0.999,
      initialReconnectDelay: 1000,
      stableConnectionMs: 30000,
    })
    const reconnectAfter = async () => {
      const before = FakeSocket.instances.length
      let waited = 0
      while (FakeSocket.instances.length === before) {
        await vi.advanceTimersByTimeAsync(100)
        waited += 100
      }
      delays.push(waited)
    }
    client.connect()
    // Accepted and immediately dropped, twice: the delay keeps growing.
    latest().open()
    latest().serverClose(1006)
    await reconnectAfter()
    latest().open()
    latest().serverClose(1006)
    await reconnectAfter()
    expect(delays[1]).toBeGreaterThan(delays[0])

    // Stable for 30 s: the next drop starts from the base delay again.
    latest().open()
    await vi.advanceTimersByTimeAsync(30_000)
    latest().serverClose(1006)
    await reconnectAfter()
    expect(delays[2]).toBeLessThanOrEqual(1000)
    client.disconnect()
  })

  it('reconnect() opens a new socket at once and re-sends the subscriptions', async () => {
    const client = new WebSocketClient({ url: 'ws://x/api/v1/ws' })
    client.connect()
    latest().open()
    client.subscribe('tenant:t1', () => {}).catch(() => {})
    const first = latest()

    client.reconnect()
    expect(FakeSocket.instances).toHaveLength(2)
    expect(first.readyState).toBe(FakeSocket.CLOSED)
    // The old socket's late close must not schedule anything.
    first.onclose?.({ code: 1000, reason: '' })

    latest().open()
    const subs = latest()
      .sent.map((s) => JSON.parse(s))
      .filter((m) => m.type === 'subscribe')
    expect(subs.map((m) => m.channel)).toEqual(['tenant:t1'])
    client.disconnect()
  })

  it('treats a FORBIDDEN or RATE_LIMITED reply as a warning, not an error', () => {
    const client = new WebSocketClient({ url: 'ws://x/api/v1/ws' })
    client.connect()
    latest().open()
    for (const code of ['FORBIDDEN', 'RATE_LIMITED']) {
      latest().onmessage?.({
        data: JSON.stringify({ type: 'error', data: { code, message: 'no' }, timestamp: 1 }),
      })
    }
    expect(devLog.error).not.toHaveBeenCalled()
    client.disconnect()
  })
})
