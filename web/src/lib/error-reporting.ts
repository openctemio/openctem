/**
 * Error Reporting Utility
 *
 * Errors are logged to the console in development and reported to the API
 * by kind only (`@/lib/client-errors`): no message, stack or user detail
 * leaves the browser. The operator is alerted when error kinds spike
 * (api/docs/operations/monitoring.md, WebClientErrors).
 *
 * Usage:
 * ```typescript
 * import { reportError, reportRouteError } from '@/lib/error-reporting'
 *
 * // General error
 * reportError(error, { context: 'User action' })
 *
 * // Route-specific error (in error.tsx)
 * reportRouteError(error, '/dashboard', { digest: error.digest })
 * ```
 */

import { classifyError, reportClientError } from '@/lib/client-errors'

interface ErrorContext {
  /**
   * Additional context about where/why the error occurred
   */
  context?: string

  /**
   * Additional metadata (development console only, never sent)
   */
  metadata?: Record<string, unknown>

  /**
   * Error severity level
   */
  level?: 'fatal' | 'error' | 'warning' | 'info'
}

/**
 * Report error
 * Logs to console in development; errors (not warnings or info) are counted
 * by kind on the API.
 *
 * @param error - The error to report
 * @param context - Additional context about the error
 */
export function reportError(error: Error | unknown, context?: ErrorContext): void {
  const level = context?.level || 'error'

  if (process.env.NODE_ENV === 'development') {
    const errorMessage = error instanceof Error ? error.message : String(error)
    const errorStack = error instanceof Error ? error.stack : undefined
    console.group(`[${level.toUpperCase()}] Error Report`)
    console.error('Message:', errorMessage)
    if (errorStack) console.error('Stack:', errorStack)
    if (context?.context) console.info('Context:', context.context)
    if (context?.metadata) console.info('Metadata:', context.metadata)
    console.groupEnd()
  }

  if (level === 'error' || level === 'fatal') {
    reportClientError(classifyError(error, 'other'))
  }
}

/**
 * Report route-specific error (for use in error.tsx files): counted as a
 * render error, or chunk_load when a code chunk failed to load.
 *
 * @param error - The error object from Next.js error boundary
 * @param route - The route where the error occurred (development console only)
 * @param _extra - Additional error info (digest, etc.) - not sent
 */
export function reportRouteError(
  error: Error & { digest?: string },
  route: string,
  _extra?: Record<string, unknown>
): void {
  if (process.env.NODE_ENV === 'development') {
    console.error(`[Route Error: ${route}]`, error)
  }
  reportClientError(classifyError(error, 'render'))
}

/**
 * Report warning (non-critical error)
 */
export function reportWarning(message: string, context?: Omit<ErrorContext, 'level'>): void {
  reportError(new Error(message), { ...context, level: 'warning' })
}

/**
 * Report info (for tracking)
 */
export function reportInfo(message: string, context?: Omit<ErrorContext, 'level'>): void {
  reportError(new Error(message), { ...context, level: 'info' })
}

// Export type for use in components
export type { ErrorContext }
