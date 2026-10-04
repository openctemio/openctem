/**
 * WebSocket channel hooks
 *
 * Subscribe components to real-time channels on the global connection, which
 * WebSocketProvider owns (authentication, reconnection, session binding).
 */

'use client'

import { useEffect, useRef, useCallback, useState } from 'react'
import { devLog } from '@/lib/logger'
import {
  WebSocketClient,
  getWebSocketClient,
  type ChannelType,
  makeChannel,
  userChannelId,
} from '@/lib/websocket'
import { useWebSocket } from '@/context/websocket-provider'

// ============================================
// CHANNEL SUBSCRIPTION HOOK
// ============================================

interface UseChannelOptions<T> {
  /** Channel type (e.g., 'finding', 'scan') */
  channelType: ChannelType
  /** Channel ID (e.g., finding ID, scan ID) */
  channelId: string | null
  /** Whether the subscription is enabled (default: true) */
  enabled?: boolean
  /** Callback when data is received */
  onData?: (data: T) => void
}

interface UseChannelReturn<T> {
  /** Latest data received from the channel */
  data: T | null
  /** Whether currently subscribed */
  isSubscribed: boolean
  /** Clear the current data */
  clearData: () => void
}

/**
 * Hook to subscribe to a specific WebSocket channel.
 * Automatically subscribes when the channel changes and unsubscribes on unmount.
 *
 * @example
 * ```tsx
 * const { data, isSubscribed } = useChannel<ActivityEventData>({
 *   channelType: 'finding',
 *   channelId: findingId,
 *   onData: (activity) => {
 *     // Handle new activity
 *     mutateActivities()
 *   }
 * })
 * ```
 */
export function useChannel<T = unknown>(options: UseChannelOptions<T>): UseChannelReturn<T> {
  const { channelType, channelId, enabled = true, onData } = options
  const { isConnected } = useWebSocket()

  const [data, setData] = useState<T | null>(null)
  const [isSubscribed, setIsSubscribed] = useState(false)
  const callbackRef = useRef(onData)

  // Keep callback ref updated
  useEffect(() => {
    callbackRef.current = onData
  }, [onData])

  // Subscribe/unsubscribe when channel changes or connection state changes
  useEffect(() => {
    if (!enabled || !channelId) {
      setIsSubscribed(false)
      return
    }

    // Wait for WebSocket client to be initialized and connected
    let client: WebSocketClient | null = null
    try {
      client = getWebSocketClient()
    } catch {
      // Client not initialized yet — will retry when isConnected changes
      return
    }

    if (!client) return

    const channel = makeChannel(channelType, channelId)

    const handleData = (eventData: T) => {
      setData(eventData)
      callbackRef.current?.(eventData)
    }

    // Subscribe
    client
      .subscribe<T>(channel, handleData)
      .then(() => {
        setIsSubscribed(true)
      })
      .catch((error) => {
        devLog.error('[useChannel] Subscribe error:', error)
        // If we get an error (like timeout), don't treat it as fatally unsubscribed
        // since the WS client will try to resubscribe on reconnect anyway,
        // but we'll set isSubscribed false for UI purposes.
        setIsSubscribed(false)
      })

    // Cleanup: unsubscribe
    return () => {
      client?.unsubscribe(channel, handleData).catch(() => {
        // Ignore unsubscribe errors on cleanup
      })
      setIsSubscribed(false)
    }
  }, [channelType, channelId, enabled, isConnected])

  const clearData = useCallback(() => {
    setData(null)
  }, [])

  return {
    data,
    isSubscribed,
    clearData,
  }
}

// ============================================
// CONVENIENCE HOOKS
// ============================================

/**
 * Hook to subscribe to finding activity updates
 */
export function useFindingChannel<T = unknown>(
  findingId: string | null,
  options: { enabled?: boolean; onData?: (data: T) => void } = {}
) {
  return useChannel<T>({
    channelType: 'finding',
    channelId: findingId,
    ...options,
  })
}

/**
 * Hook to subscribe to scan progress updates
 */
export function useScanChannel<T = unknown>(
  scanId: string | null,
  options: { enabled?: boolean; onData?: (data: T) => void } = {}
) {
  return useChannel<T>({
    channelType: 'scan',
    channelId: scanId,
    ...options,
  })
}

/**
 * Hook to subscribe to AI triage updates
 */
export function useTriageChannel<T = unknown>(
  findingId: string | null,
  options: { enabled?: boolean; onData?: (data: T) => void } = {}
) {
  return useChannel<T>({
    channelType: 'triage',
    channelId: findingId,
    ...options,
  })
}

/**
 * Hook to subscribe to the signed-in user's own in-app notifications.
 * Notifications are never sent on the tenant channel: each one is pushed only
 * to the users it is addressed to (and whose preferences allow it).
 */
export function useUserNotificationChannel<T = unknown>(
  tenantId: string | null | undefined,
  userId: string | null | undefined,
  options: { enabled?: boolean; onData?: (data: T) => void } = {}
) {
  return useChannel<T>({
    channelType: 'user',
    channelId: tenantId && userId ? userChannelId(tenantId, userId) : null,
    ...options,
  })
}

/**
 * Hook to subscribe to tenant-wide events (e.g. module toggles)
 */
export function useTenantChannel<T = unknown>(
  tenantId: string | null,
  options: { enabled?: boolean; onData?: (data: T) => void } = {}
) {
  return useChannel<T>({
    channelType: 'tenant',
    channelId: tenantId,
    ...options,
  })
}

/**
 * Hook to subscribe to group membership/scope rule changes
 */
export function useGroupChannel<T = unknown>(
  groupId: string | null,
  options: { enabled?: boolean; onData?: (data: T) => void } = {}
) {
  return useChannel<T>({
    channelType: 'group',
    channelId: groupId,
    ...options,
  })
}

// Re-export types for convenience
export type { ConnectionState } from '@/lib/websocket'
