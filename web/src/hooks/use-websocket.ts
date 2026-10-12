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
 * Subscribe to the run:{id} channel of every run in `runIds` (the live runs
 * of a list) and call `onChange` on any of their change notices. Returns true
 * while every one of them is subscribed: the list may then stop polling for
 * them and rely on the notices; while it is false (socket down, a subscription
 * refused) it keeps polling as the fallback.
 *
 * The server checks each subscription like a read of that run (tenant, and
 * findings:read plus data scope for a run about a finding); a notice carries
 * only the run id, and the list re-reads through the gated endpoints.
 */
export function useRunChannels(runIds: string[], onChange: () => void): boolean {
  const { isConnected } = useWebSocket()
  const [subscribed, setSubscribed] = useState<string>('')
  const callbackRef = useRef(onChange)
  useEffect(() => {
    callbackRef.current = onChange
  }, [onChange])

  const idsKey = [...new Set(runIds)].sort().join(',')

  useEffect(() => {
    if (!idsKey || !isConnected) return
    let client: WebSocketClient | null = null
    try {
      client = getWebSocketClient()
    } catch {
      return
    }
    if (!client) return
    const channels = idsKey.split(',').map((id) => makeChannel('run', id))
    const handler = () => callbackRef.current?.()
    let cancelled = false
    Promise.all(channels.map((c) => client!.subscribe(c, handler)))
      .then(() => {
        if (!cancelled) setSubscribed(idsKey)
      })
      .catch((error) => {
        devLog.error('[useRunChannels] Subscribe error:', error)
        if (!cancelled) setSubscribed('')
      })
    return () => {
      cancelled = true
      setSubscribed('')
      for (const c of channels) client?.unsubscribe(c, handler).catch(() => {})
    }
  }, [idsKey, isConnected])

  return isConnected && idsKey !== '' && subscribed === idsKey
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
