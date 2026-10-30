/**
 * Notification Outbox Types
 *
 * Types for the notification outbox queue management.
 * Tenants can monitor and manage their notification delivery queue.
 */

/**
 * Outbox entry status
 */
export type OutboxStatus = 'pending' | 'processing' | 'completed' | 'failed' | 'dead'

/**
 * Outbox entry severity
 */
export type OutboxSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

/**
 * Outbox entry response from API
 */
export interface OutboxEntry {
  id: string
  event_type: string
  aggregate_type: string
  aggregate_id?: string
  title: string
  body?: string
  severity: OutboxSeverity
  url?: string
  status: OutboxStatus
  retry_count: number
  max_retries: number
  last_error?: string
  scheduled_at: string
  locked_at?: string
  processed_at?: string
  created_at: string
  updated_at: string
  metadata?: Record<string, unknown>
}

/**
 * Outbox statistics response
 */
export interface OutboxStats {
  pending: number
  processing: number
  completed: number
  failed: number
  dead: number
  total: number
}

/**
 * Outbox list response with pagination
 */
export interface OutboxListResponse {
  data: OutboxEntry[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

/**
 * Outbox list filters
 */
export interface OutboxListFilters {
  status?: OutboxStatus
  page?: number
  per_page?: number
}
