/**
 * WebSocket Types
 *
 * TypeScript types for WebSocket communication with the backend.
 * Mirrors the types defined in api/internal/infra/websocket/types.go
 */

// ============================================
// MESSAGE TYPES
// ============================================

/** Message types sent from client to server */
export type ClientMessageType = 'subscribe' | 'unsubscribe' | 'ping'

/** Message types sent from server to client */
export type ServerMessageType = 'subscribed' | 'unsubscribed' | 'event' | 'error' | 'pong'

/** All possible message types */
export type MessageType = ClientMessageType | ServerMessageType

// ============================================
// CHANNEL TYPES
// ============================================

/**
 * Channel types for WebSocket subscriptions
 * Format: {type}:{id}
 */
export type ChannelType =
  | 'finding' // finding:{id} - Activity updates for a finding
  | 'scan' // scan:{id} - Scan progress updates
  | 'tenant' // tenant:{id} - Events for every tenant member (module toggles); never notifications
  | 'user' // user:{tenant_id}:{user_id} - The signed-in user's own notifications
  | 'triage' // triage:{finding_id} - AI triage progress
  | 'group' // group:{id} - Group membership/scope rule changes
  | 'run' // run:{id} - A scan run changed (the live run map refreshes)

/**
 * Create a channel string from type and ID
 */
export function makeChannel(type: ChannelType, id: string): string {
  return `${type}:${id}`
}

/**
 * Channel id of the signed-in user's own notification channel
 * (`user:{tenant_id}:{user_id}`). The server only lets a connection subscribe
 * to the channel of the user and tenant it authenticated as.
 */
export function userChannelId(tenantId: string, userId: string): string {
  return `${tenantId}:${userId}`
}

/**
 * Parse a channel string into type and ID
 */
export function parseChannel(channel: string): { type: ChannelType; id: string } | null {
  const colonIndex = channel.indexOf(':')
  if (colonIndex === -1) return null
  return {
    type: channel.substring(0, colonIndex) as ChannelType,
    id: channel.substring(colonIndex + 1),
  }
}

// ============================================
// MESSAGE STRUCTURES
// ============================================

/** Base message structure */
export interface WebSocketMessage {
  type: MessageType
  channel?: string
  // `unknown`, not `any`: this is the pre-narrowing shape returned by
  // JSON.parse before the `type` discriminant is read. Every branch that
  // actually reads the payload narrows to EventMessage<T> or ErrorMessage
  // first, both of which type `data` properly, so nothing here needs to be
  // dereferenced blind.
  data?: unknown
  timestamp: number
  request_id?: string
}

/** Subscribe request from client */
export interface SubscribeRequest {
  type: 'subscribe'
  channel: string
  request_id?: string
}

/** Unsubscribe request from client */
export interface UnsubscribeRequest {
  type: 'unsubscribe'
  channel: string
  request_id?: string
}

/** Ping request from client */
export interface PingRequest {
  type: 'ping'
}

/** Subscribed confirmation from server */
export interface SubscribedResponse {
  type: 'subscribed'
  channel: string
  timestamp: number
  request_id?: string
}

/** Unsubscribed confirmation from server */
export interface UnsubscribedResponse {
  type: 'unsubscribed'
  channel: string
  timestamp: number
  request_id?: string
}

/** Event from server */
export interface EventMessage<T = unknown> {
  type: 'event'
  channel: string
  data: T
  timestamp: number
}

/** Error from server */
export interface ErrorMessage {
  type: 'error'
  data: {
    code: string
    message: string
  }
  timestamp: number
  request_id?: string
}

/** Pong response from server */
export interface PongResponse {
  type: 'pong'
  timestamp: number
}

// ============================================
// CONNECTION STATES
// ============================================

/**
 * WebSocket connection states
 */
export type ConnectionState = 'connecting' | 'connected' | 'disconnected' | 'reconnecting' | 'error'

/**
 * Close codes the server sends when it ends a connection on its own
 * (api/internal/infra/websocket/types.go, RFC-045 §5.4).
 */
export const WS_CLOSE = {
  /** Client-initiated normal close: do not reconnect. */
  NORMAL: 1000,
  /** Message rate limit abused. */
  POLICY_VIOLATION: 1008,
  /**
   * The credential is no longer valid: the access token expired, the session
   * was signed out or revoked, or membership/role changed. Reconnect (the
   * upgrade re-runs every gate); refresh the session if that fails.
   */
  UNAUTHORIZED: 4401,
  /** Too many sockets for this user: back off at the maximum delay. */
  TOO_MANY_CONNECTIONS: 4429,
} as const

// ============================================
// EVENT DATA TYPES
// ============================================

/** Activity event data from finding channel */
export interface ActivityEventData {
  type: 'activity_created'
  activity: {
    id: string
    finding_id: string
    tenant_id: string
    activity_type: string
    actor_id?: string
    actor_type: string
    actor_name?: string
    actor_email?: string
    changes?: Record<string, unknown>
    created_at: string
  }
}

/** AI Triage event data */
export interface TriageEventData {
  type: 'triage_started' | 'triage_progress' | 'triage_completed' | 'triage_failed'
  finding_id: string
  status?: string
  progress?: number
  result?: {
    severity?: string
    priority?: string
    analysis?: string
  }
  error?: string
}

/** Scan progress event data */
export interface ScanEventData {
  type: 'scan_started' | 'scan_progress' | 'scan_completed' | 'scan_failed'
  scan_id: string
  status?: string
  progress?: number
  findings_count?: number
  error?: string
}

/** Scope change event data from group channel */
export interface ScopeChangeEventData {
  event_type: 'scope_rule_evaluated' | 'scope_rule_reconciled'
  group_id: string
  assets_added: number
  assets_removed: number
}
