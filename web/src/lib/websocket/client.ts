/**
 * WebSocket Client
 *
 * A robust WebSocket client with:
 * - Session-cookie authentication: the browser sends the httpOnly access-token
 *   cookie on the same-origin upgrade; no credential is ever put in the URL
 * - Automatic reconnection with exponential backoff and full jitter
 * - Server close codes: 4401 (session ended / access changed) reconnects and
 *   refreshes the session when needed, 4429 (too many sockets) backs off
 * - Channel subscription management (re-subscribed after every reconnect)
 * - Connection state tracking
 *
 * Design: api/docs/rfcs/RFC-045-websocket-auth.md.
 */

import type {
  ConnectionState,
  WebSocketMessage,
  SubscribeRequest,
  UnsubscribeRequest,
  EventMessage,
  ErrorMessage,
} from './types'
import { WS_CLOSE } from './types'

import { devLog } from '@/lib/logger'

// ============================================
// CONFIGURATION
// ============================================

/** Default reconnection settings */
const DEFAULT_CONFIG = {
  /** Base of the exponential backoff in ms */
  initialReconnectDelay: 1000,
  /** Maximum reconnect delay in ms (the backoff cap) */
  maxReconnectDelay: 30000,
  /** Maximum number of consecutive failed reconnects (0 = infinite) */
  maxReconnectAttempts: 10,
  /** A connection must stay up this long before the backoff resets */
  stableConnectionMs: 30000,
  /**
   * Spread of the reconnect after a 4401 close. Every tab's socket closes at
   * the same access-token expiry; the jitter keeps them from reconnecting
   * (and possibly refreshing) in the same instant.
   */
  authReconnectJitterMs: 3000,
  /** Ping interval in ms (keep-alive) */
  pingInterval: 30000,
  /** Pong timeout in ms (consider disconnected if no pong received) */
  pongTimeout: 10000,
}

export interface WebSocketClientConfig {
  /** WebSocket URL (e.g., wss://ctem.example.com/api/v1/ws) */
  url: string
  /**
   * Refreshes the session (the access-token cookie). Called once when a
   * reconnect after a 4401 close fails before the socket opens, which is how
   * an expired cookie shows up (the browser exposes no handshake status).
   * Resolve false when the session cannot be refreshed: the client then stops
   * reconnecting.
   */
  onAuthExpired?: () => Promise<boolean>
  /** Reconnection settings */
  initialReconnectDelay?: number
  maxReconnectDelay?: number
  maxReconnectAttempts?: number
  stableConnectionMs?: number
  authReconnectJitterMs?: number
  pingInterval?: number
  pongTimeout?: number
  /** Random source in [0, 1) for jitter (tests inject a fixed one). */
  random?: () => number
  /** Callback when connection state changes */
  onStateChange?: (state: ConnectionState) => void
  /** Callback when an error occurs */
  onError?: (error: Error) => void
  /** Callback when connection is established */
  onConnect?: () => void
  /** Callback when connection is closed */
  onDisconnect?: (reason?: string) => void
}

/**
 * Full-jitter backoff (AWS Architecture Blog, "Exponential Backoff and
 * Jitter"): a uniformly random delay in [0, min(cap, base * 2^attempt)).
 */
export function fullJitterDelay(
  attempt: number,
  base: number,
  cap: number,
  random: () => number = Math.random
): number {
  const ceiling = Math.min(cap, base * Math.pow(2, attempt))
  return Math.floor(random() * ceiling)
}

// ============================================
// CLIENT CLASS
// ============================================

type InternalConfig = Required<Omit<WebSocketClientConfig, 'onAuthExpired'>> & {
  onAuthExpired?: () => Promise<boolean>
}

export class WebSocketClient {
  private ws: WebSocket | null = null
  private config: InternalConfig
  private state: ConnectionState = 'disconnected'
  private reconnectAttempts = 0
  private reconnectTimeout: ReturnType<typeof setTimeout> | null = null
  private stableTimeout: ReturnType<typeof setTimeout> | null = null
  private pingTimeout: ReturnType<typeof setTimeout> | null = null
  private pongTimeout: ReturnType<typeof setTimeout> | null = null

  /** The last close was 4401 and no connection has opened since. */
  private authExpired = false
  /** onAuthExpired already ran for the current 4401. */
  private authRefreshTried = false
  /** The current socket reached OPEN. */
  private opened = false

  /**
   * Active subscriptions: channel -> Set of callbacks.
   *
   * Stored as `(data: unknown) => void` because one map holds callbacks for
   * every channel, each with its own payload type. subscribe<T> keeps the
   * caller's type at the boundary; the cast on insert is the one place the
   * two meet.
   */
  private subscriptions = new Map<string, Set<(data: unknown) => void>>()
  /** Pending subscription requests: requestId -> resolve/reject */
  private pendingRequests = new Map<string, { resolve: () => void; reject: (err: Error) => void }>()
  /** Request ID counter */
  private requestIdCounter = 0

  constructor(config: WebSocketClientConfig) {
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
      random: config.random ?? Math.random,
      onStateChange: config.onStateChange ?? (() => {}),
      onError: config.onError ?? ((err) => devLog.warn('[WebSocket] Error:', err)),
      onConnect: config.onConnect ?? (() => {}),
      onDisconnect: config.onDisconnect ?? (() => {}),
    }
  }

  // ============================================
  // PUBLIC API
  // ============================================

  /**
   * Connect to the WebSocket server
   */
  connect(): void {
    if (
      this.ws &&
      (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)
    ) {
      devLog.log('[WebSocket] Already connected or connecting')
      return
    }

    this.setState('connecting')
    this.createConnection()
  }

  /**
   * Disconnect from the WebSocket server
   */
  disconnect(): void {
    this.clearTimers()
    this.reconnectAttempts = 0

    // Reject all pending requests
    for (const [, handlers] of this.pendingRequests.entries()) {
      handlers.reject(new Error('WebSocket client disconnected'))
    }
    this.pendingRequests.clear()

    this.closeSocket('Client disconnect')

    this.setState('disconnected')
    this.config.onDisconnect?.('Client disconnect')
  }

  /**
   * Close the current socket and open a new one at once, keeping the
   * subscriptions (they are re-sent on open). Used when the session changes
   * under an open socket, e.g. after switching organization: the socket is
   * bound to the tenant of the token it was opened with.
   */
  reconnect(): void {
    this.clearTimers()
    this.reconnectAttempts = 0
    this.authExpired = false
    this.authRefreshTried = false
    this.closeSocket('Reconnect')
    this.setState('connecting')
    this.createConnection()
  }

  /**
   * Subscribe to a channel
   * @param channel Channel name (e.g., "finding:abc-123")
   * @param callback Function to call when events are received
   * @returns Promise that resolves when subscription is confirmed
   */
  async subscribe<T = unknown>(channel: string, callback: (data: T) => void): Promise<void> {
    // Add callback to subscriptions
    if (!this.subscriptions.has(channel)) {
      this.subscriptions.set(channel, new Set())
    }
    this.subscriptions.get(channel)!.add(callback as (data: unknown) => void)

    // If not connected, subscription will be sent on reconnect
    if (this.state !== 'connected') {
      devLog.log('[WebSocket] Queued subscription for', channel)
      return
    }

    // Send subscribe request
    const requestId = this.generateRequestId()
    const request: SubscribeRequest = {
      type: 'subscribe',
      channel,
      request_id: requestId,
    }

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(requestId, { resolve, reject })
      this.send(request)

      // Timeout after 10 seconds
      setTimeout(() => {
        if (this.pendingRequests.has(requestId)) {
          this.pendingRequests.delete(requestId)
          reject(new Error('Subscribe request timed out'))
        }
      }, 10000)
    })
  }

  /**
   * Unsubscribe from a channel
   * @param channel Channel name
   * @param callback Optional: specific callback to remove. If not provided, removes all callbacks.
   */
  async unsubscribe<T = unknown>(channel: string, callback?: (data: T) => void): Promise<void> {
    const callbacks = this.subscriptions.get(channel)
    if (!callbacks) return

    if (callback) {
      // Mirrors the cast in subscribe(): callers hold a typed callback, the
      // map holds them erased. Set.delete matches on identity, so the cast
      // only has to satisfy the compiler — it removes exactly the function
      // that was inserted.
      callbacks.delete(callback as (data: unknown) => void)
      // If there are still other callbacks, don't unsubscribe from server
      if (callbacks.size > 0) return
    }

    // Remove all callbacks for this channel
    this.subscriptions.delete(channel)

    // Send unsubscribe request if connected
    if (this.state !== 'connected') return

    const requestId = this.generateRequestId()
    const request: UnsubscribeRequest = {
      type: 'unsubscribe',
      channel,
      request_id: requestId,
    }

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(requestId, { resolve, reject })
      this.send(request)

      setTimeout(() => {
        if (this.pendingRequests.has(requestId)) {
          this.pendingRequests.delete(requestId)
          reject(new Error('Unsubscribe request timed out'))
        }
      }, 10000)
    })
  }

  /**
   * Get current connection state
   */
  getState(): ConnectionState {
    return this.state
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.state === 'connected' && this.ws?.readyState === WebSocket.OPEN
  }

  // ============================================
  // PRIVATE METHODS
  // ============================================

  private createConnection(): void {
    // The URL carries no credential: the browser attaches the session cookie
    // to the same-origin upgrade.
    devLog.log('[WebSocket] Connecting to:', this.config.url)
    this.opened = false
    try {
      this.ws = new WebSocket(this.config.url)
      this.setupEventHandlers()
    } catch (error) {
      devLog.error('[WebSocket] Failed to create connection:', error)
      this.handleError(error instanceof Error ? error : new Error(String(error)))
    }
  }

  /** Detach and close the current socket without triggering a reconnect. */
  private closeSocket(reason: string): void {
    const ws = this.ws
    this.ws = null
    if (!ws) return
    ws.onopen = null
    ws.onclose = null
    ws.onerror = null
    ws.onmessage = null
    try {
      ws.close(WS_CLOSE.NORMAL, reason)
    } catch {
      // Already closing or closed.
    }
  }

  private setupEventHandlers(): void {
    const ws = this.ws
    if (!ws) return

    ws.onopen = () => {
      devLog.log('[WebSocket] Connected')
      this.opened = true
      this.authExpired = false
      this.authRefreshTried = false
      this.setState('connected')
      this.config.onConnect?.()
      this.startPingInterval()
      // Reset the backoff only once the connection has proven stable, so a
      // server that accepts and immediately drops does not reconnect at the
      // base delay forever.
      this.stableTimeout = setTimeout(() => {
        this.reconnectAttempts = 0
      }, this.config.stableConnectionMs)
      this.resubscribeAll()
    }

    ws.onclose = (event) => {
      if (this.ws !== ws) return // a socket we already replaced
      devLog.log('[WebSocket] Disconnected:', event.code, event.reason)
      this.clearTimers()
      const wasOpen = this.opened
      this.ws = null

      switch (event.code) {
        case WS_CLOSE.NORMAL:
          this.setState('disconnected')
          this.config.onDisconnect?.(event.reason)
          return
        case WS_CLOSE.UNAUTHORIZED:
          // Session expired, revoked or access changed. Reconnect soon: the
          // cookie has usually been refreshed already; if not, the failed
          // attempt below triggers one refresh.
          this.authExpired = true
          this.authRefreshTried = false
          this.scheduleReconnectIn(
            Math.floor(this.config.random() * this.config.authReconnectJitterMs)
          )
          return
        case WS_CLOSE.TOO_MANY_CONNECTIONS:
          this.scheduleReconnectIn(
            Math.floor(this.config.maxReconnectDelay * (0.5 + this.config.random() / 2))
          )
          return
      }

      if (!wasOpen && this.authExpired && !this.authRefreshTried && this.config.onAuthExpired) {
        // The reconnect after a 4401 was refused before opening: the session
        // cookie is gone or stale. Refresh it once, then try again.
        this.authRefreshTried = true
        this.refreshThenReconnect(this.config.onAuthExpired)
        return
      }

      this.scheduleReconnect()
    }

    ws.onerror = () => {
      // A WebSocket error event carries no actionable detail and is always
      // followed by onclose, which owns reconnection. Log at warn (error would
      // surface in the dev overlay as a blocking issue) and let onclose retry —
      // routing through handleError here would double-schedule the reconnect.
      devLog.warn('[WebSocket] Connection error (will retry)')
      this.setState('error')
    }

    ws.onmessage = (event) => {
      this.handleMessage(event.data)
    }
  }

  private refreshThenReconnect(refresh: () => Promise<boolean>): void {
    this.setState('reconnecting')
    refresh()
      .then((ok) => {
        if (!ok) {
          // The session cannot be renewed; the REST client sends the user
          // to sign in. Stop here instead of retrying a dead session.
          devLog.warn('[WebSocket] Session refresh failed; not reconnecting')
          this.setState('error')
          this.config.onError?.(new Error('Session expired'))
          return
        }
        if (this.state === 'disconnected') return // disconnect() meanwhile
        this.createConnection()
      })
      .catch((error) => {
        this.handleError(error instanceof Error ? error : new Error(String(error)))
      })
  }

  private handleMessage(data: string): void {
    try {
      const message = JSON.parse(data) as WebSocketMessage

      switch (message.type) {
        case 'pong':
          this.handlePong()
          break

        case 'subscribed':
          this.handleSubscribed(message)
          break

        case 'unsubscribed':
          this.handleUnsubscribed(message)
          break

        case 'event':
          this.handleEvent(message as EventMessage)
          break

        case 'error':
          this.handleServerError(message as ErrorMessage)
          break

        default:
          devLog.log('[WebSocket] Unknown message type:', message.type)
      }
    } catch (error) {
      devLog.error('[WebSocket] Failed to parse message:', error)
    }
  }

  private handlePong(): void {
    // Clear pong timeout
    if (this.pongTimeout) {
      clearTimeout(this.pongTimeout)
      this.pongTimeout = null
    }
  }

  private handleSubscribed(message: WebSocketMessage): void {
    devLog.log('[WebSocket] Subscribed to:', message.channel)
    const requestId = message.request_id
    if (requestId && this.pendingRequests.has(requestId)) {
      this.pendingRequests.get(requestId)!.resolve()
      this.pendingRequests.delete(requestId)
    }
  }

  private handleUnsubscribed(message: WebSocketMessage): void {
    devLog.log('[WebSocket] Unsubscribed from:', message.channel)
    const requestId = message.request_id
    if (requestId && this.pendingRequests.has(requestId)) {
      this.pendingRequests.get(requestId)!.resolve()
      this.pendingRequests.delete(requestId)
    }
  }

  private handleEvent(message: EventMessage): void {
    const channel = message.channel
    const callbacks = this.subscriptions.get(channel)

    if (callbacks && callbacks.size > 0) {
      callbacks.forEach((callback) => {
        try {
          callback(message.data)
        } catch (error) {
          devLog.error('[WebSocket] Callback error for channel', channel, error)
        }
      })
    }
  }

  private handleServerError(message: ErrorMessage): void {
    const requestId = message.request_id
    if (requestId && this.pendingRequests.has(requestId)) {
      this.pendingRequests.get(requestId)!.reject(new Error(message.data.message))
      this.pendingRequests.delete(requestId)
    }

    // FORBIDDEN on channel subscribe is common during page transitions and
    // after an organization switch; RATE_LIMITED means this tab sends too
    // much. Neither is a crash: warn, do not error.
    const code = message.data.code
    if (code === 'FORBIDDEN' || code === 'UNAUTHORIZED' || code === 'RATE_LIMITED') {
      devLog.warn('[WebSocket] Server refused a request:', code, message.data.message)
      return
    }
    devLog.error('[WebSocket] Server error:', message.data)
  }

  private handleError(error: Error): void {
    this.setState('error')
    this.config.onError?.(error)
    this.scheduleReconnect()
  }

  private scheduleReconnect(): void {
    // Check max attempts
    if (
      this.config.maxReconnectAttempts > 0 &&
      this.reconnectAttempts >= this.config.maxReconnectAttempts
    ) {
      devLog.warn('[WebSocket] Max reconnect attempts reached')
      this.setState('error')
      this.config.onError?.(new Error('Max reconnect attempts reached'))
      return
    }

    const delay = fullJitterDelay(
      this.reconnectAttempts,
      this.config.initialReconnectDelay,
      this.config.maxReconnectDelay,
      this.config.random
    )
    this.reconnectAttempts++

    devLog.log(
      `[WebSocket] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.config.maxReconnectAttempts || 'unlimited'})`
    )
    this.scheduleReconnectIn(delay)
  }

  private scheduleReconnectIn(delay: number): void {
    this.setState('reconnecting')
    if (this.reconnectTimeout) clearTimeout(this.reconnectTimeout)
    this.reconnectTimeout = setTimeout(() => {
      this.reconnectTimeout = null
      this.createConnection()
    }, delay)
  }

  private resubscribeAll(): void {
    // Re-subscribe to all channels after reconnect
    for (const channel of this.subscriptions.keys()) {
      const request: SubscribeRequest = {
        type: 'subscribe',
        channel,
        request_id: this.generateRequestId(),
      }
      this.send(request)
    }
  }

  private startPingInterval(): void {
    this.pingTimeout = setInterval(() => {
      if (this.state === 'connected') {
        this.send({ type: 'ping' })

        // Set pong timeout
        this.pongTimeout = setTimeout(() => {
          devLog.warn('[WebSocket] Pong timeout, reconnecting...')
          this.ws?.close()
        }, this.config.pongTimeout)
      }
    }, this.config.pingInterval)
  }

  private clearTimers(): void {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout)
      this.reconnectTimeout = null
    }
    if (this.stableTimeout) {
      clearTimeout(this.stableTimeout)
      this.stableTimeout = null
    }
    if (this.pingTimeout) {
      clearInterval(this.pingTimeout)
      this.pingTimeout = null
    }
    if (this.pongTimeout) {
      clearTimeout(this.pongTimeout)
      this.pongTimeout = null
    }
  }

  private send(data: unknown): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data))
    }
  }

  private setState(state: ConnectionState): void {
    if (this.state !== state) {
      this.state = state
      this.config.onStateChange?.(state)
    }
  }

  private generateRequestId(): string {
    return `req-${++this.requestIdCounter}-${Date.now()}`
  }
}

// ============================================
// SINGLETON INSTANCE
// ============================================

let globalClient: WebSocketClient | null = null

/**
 * Get or create the global WebSocket client instance
 */
export function getWebSocketClient(config?: WebSocketClientConfig): WebSocketClient {
  if (!globalClient && config) {
    globalClient = new WebSocketClient(config)
  }
  if (!globalClient) {
    throw new Error('WebSocket client not initialized. Call initWebSocketClient first.')
  }
  return globalClient
}

/**
 * Initialize the global WebSocket client
 */
export function initWebSocketClient(config: WebSocketClientConfig): WebSocketClient {
  if (globalClient) {
    globalClient.disconnect()
  }
  globalClient = new WebSocketClient(config)
  return globalClient
}

/**
 * Destroy the global WebSocket client
 */
export function destroyWebSocketClient(): void {
  if (globalClient) {
    globalClient.disconnect()
    globalClient = null
  }
}
