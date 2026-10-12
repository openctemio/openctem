import { afterEach, describe, expect, it, vi } from 'vitest'
import { render } from '@testing-library/react'

// RFC-045: the provider opens the socket with the session cookie (no ticket
// fetch), hands the client the shared session refresh for 4401 recovery, and
// reconnects when the organization changes under an open socket.

const fakeClient = {
  connect: vi.fn(),
  reconnect: vi.fn(),
  disconnect: vi.fn(),
  isConnected: vi.fn(() => true),
}
const initWebSocketClient = vi.fn((cfg: unknown) => {
  void cfg
  return fakeClient
})

vi.mock('@/lib/websocket', () => ({
  initWebSocketClient: (cfg: unknown) => initWebSocketClient(cfg),
  destroyWebSocketClient: vi.fn(),
}))
vi.mock('@/context/bootstrap-provider', () => ({
  useBootstrapContextSafe: () => ({ isBootstrapped: true }),
}))
let tenantId = 'tenant-a'
vi.mock('@/context/tenant-provider', () => ({
  useCurrentTenantId: () => tenantId,
}))
const refreshSession = vi.fn(async () => true)
vi.mock('@/lib/api/client', () => ({ refreshSession: () => refreshSession() }))
vi.mock('@/lib/logger', () => ({
  devLog: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))

import { WebSocketProvider } from '../websocket-provider'

describe('WebSocketProvider', () => {
  afterEach(() => {
    vi.clearAllMocks()
    tenantId = 'tenant-a'
  })

  it('connects without fetching a ticket and wires the session refresh', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    render(
      <WebSocketProvider>
        <div />
      </WebSocketProvider>
    )
    expect(initWebSocketClient).toHaveBeenCalledTimes(1)
    const cfg = initWebSocketClient.mock.calls[0][0] as {
      url: string
      onAuthExpired: () => Promise<boolean>
    }
    expect(cfg.url).toMatch(/\/api\/v1\/ws$/)
    expect(cfg.url).not.toContain('?')
    expect(fakeClient.connect).toHaveBeenCalledTimes(1)
    expect(fetchSpy).not.toHaveBeenCalled()

    await cfg.onAuthExpired()
    expect(refreshSession).toHaveBeenCalledTimes(1)
    fetchSpy.mockRestore()
  })

  it('reconnects when the organization changes', () => {
    const { rerender } = render(
      <WebSocketProvider>
        <div />
      </WebSocketProvider>
    )
    expect(fakeClient.reconnect).not.toHaveBeenCalled()

    tenantId = 'tenant-b'
    rerender(
      <WebSocketProvider>
        <div />
      </WebSocketProvider>
    )
    expect(fakeClient.reconnect).toHaveBeenCalledTimes(1)
  })
})
