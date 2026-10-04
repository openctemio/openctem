'use client'

/**
 * WebSocket Provider
 *
 * Provides the global WebSocket connection for real-time updates.
 *
 * Authentication (RFC-045): the socket is opened on the UI's own origin and
 * the browser sends the httpOnly access-token cookie with the upgrade. The API
 * authenticates it through the same tenant gates as every tenant route (SSO
 * enforcement, IP allowlist, active membership) and checks the Origin. No
 * credential is ever put in the URL, and there is no ticket round trip.
 *
 * The server binds the socket to the session: it closes it with 4401 when the
 * access token expires, the session is signed out or revoked, or the user's
 * membership or role changes. The client then reconnects with jitter and, if
 * the reconnect is refused, refreshes the session once (refreshSession) and
 * tries again.
 */

import { createContext, useContext, useState, useCallback, useRef, useEffect, useMemo } from 'react'
import {
  WebSocketClient,
  initWebSocketClient,
  destroyWebSocketClient,
  type ConnectionState,
} from '@/lib/websocket'
import { useBootstrapContextSafe } from '@/context/bootstrap-provider'
import { useCurrentTenantId } from '@/context/tenant-provider'
import { refreshSession } from '@/lib/api/client'
import { devLog } from '@/lib/logger'
import { env } from '@/lib/env'

// ============================================
// CONTEXT
// ============================================

interface WebSocketContextValue {
  /** Current connection state */
  state: ConnectionState
  /** Whether WebSocket is connected */
  isConnected: boolean
  /** Reconnect manually */
  reconnect: () => void
}

const WebSocketContext = createContext<WebSocketContextValue | null>(null)

// ============================================
// HELPERS
// ============================================

export function buildWsUrl(): string {
  if (typeof window === 'undefined') return ''

  // An explicit WS URL wins. It must be served for the UI's site with the
  // session cookie (same site and cookie Domain), or better, on the UI's own
  // origin: the socket authenticates with the cookie, so a cross-site host
  // never gets a session.
  const explicitUrl = process.env.NEXT_PUBLIC_WS_BASE_URL || env.api.wsBaseUrl
  if (explicitUrl) {
    const wsProtocol = explicitUrl.startsWith('https') ? 'wss' : 'ws'
    const wsHost = explicitUrl.replace(/^https?:\/\//, '')
    return `${wsProtocol}://${wsHost}/api/v1/ws`
  }

  // The UI's own origin: the gateway routes /api/v1/ws to the API, and the
  // UI server (server-with-ws.mjs, or the next dev rewrite) forwards the
  // upgrade with the browser's Cookie and Origin headers.
  const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
  return `${wsProtocol}://${window.location.host}/api/v1/ws`
}

// ============================================
// PROVIDER
// ============================================

interface WebSocketProviderProps {
  children: React.ReactNode
}

export function WebSocketProvider({ children }: WebSocketProviderProps) {
  const [state, setState] = useState<ConnectionState>('disconnected')
  const clientRef = useRef<WebSocketClient | null>(null)
  const { isBootstrapped } = useBootstrapContextSafe()
  const tenantId = useCurrentTenantId()
  const connectedTenantRef = useRef<string | null>(null)

  const connect = useCallback(() => {
    const wsUrl = buildWsUrl()
    if (!wsUrl) {
      devLog.log('[WebSocket] No WebSocket URL available')
      return
    }

    if (clientRef.current) {
      // Manual reconnect: keep the client and its subscriptions.
      if (!clientRef.current.isConnected()) clientRef.current.reconnect()
      return
    }

    devLog.log('[WebSocket] Connecting to', wsUrl)
    clientRef.current = initWebSocketClient({
      url: wsUrl,
      onAuthExpired: refreshSession,
      onStateChange: (newState) => {
        devLog.log('[WebSocket] State changed:', newState)
        setState(newState)
      },
      // Connection errors are transient (auto-retried with backoff); warn so
      // they don't surface as blocking issues in the dev error overlay.
      onError: (error) => devLog.warn('[WebSocket] Connection error:', error),
    })
    clientRef.current.connect()
  }, [])

  // Connect only after bootstrap is complete (permissions/tenant context ready)
  // This prevents "Access denied to channel" errors during initial load
  useEffect(() => {
    if (!isBootstrapped) return

    connect()

    return () => {
      destroyWebSocketClient()
      clientRef.current = null
      connectedTenantRef.current = null
    }
  }, [isBootstrapped, connect])

  // The socket is bound to the organization of the token it was opened with.
  // After a switch (no page reload) open a new one for the new organization;
  // the subscriptions are re-sent and re-authorized on it.
  useEffect(() => {
    if (!tenantId) return
    const previous = connectedTenantRef.current
    connectedTenantRef.current = tenantId
    if (previous && previous !== tenantId && clientRef.current) {
      devLog.log('[WebSocket] Organization changed, reconnecting')
      clientRef.current.reconnect()
    }
  }, [tenantId])

  // Memoized so the context value identity is stable across renders — this
  // provider wraps the whole dashboard, so a fresh object each render would
  // re-render every useWebSocket() consumer.
  const value = useMemo<WebSocketContextValue>(
    () => ({ state, isConnected: state === 'connected', reconnect: connect }),
    [state, connect]
  )

  return <WebSocketContext.Provider value={value}>{children}</WebSocketContext.Provider>
}

// ============================================
// HOOK
// ============================================

export function useWebSocket() {
  const context = useContext(WebSocketContext)
  if (!context) {
    return {
      state: 'disconnected' as ConnectionState,
      isConnected: false,
      reconnect: () => {},
    }
  }
  return context
}
