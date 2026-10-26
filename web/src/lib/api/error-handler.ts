/**
 * API Error Handler
 *
 * Centralized error handling for API requests
 */

import { toast } from 'sonner'
import type { ApiError } from './types'
import { devLog } from '@/lib/logger'
import { IP_NOT_ALLOWED_CODE, IP_NOT_ALLOWED_MESSAGE, notifyIpNotAllowed } from './ip-not-allowed'
import { describePermissionDenied } from './permission-denied'
import { apiErrorMessage } from './error-message'

// ============================================
// ERROR CLASSES
// ============================================

/**
 * 403 code for a change only an approver may make (e.g. marking a finding false
 * positive). The message names the permission the approver needs.
 */
export const APPROVAL_REQUIRED_CODE = 'APPROVAL_REQUIRED'

/**
 * Custom API Client Error
 */
export class ApiClientError extends Error {
  code: string
  statusCode: number
  details?: Record<string, unknown>
  /** The server's id for the failed request (`request_id`), to quote to support. */
  requestId?: string

  constructor(
    message: string,
    code: string = 'UNKNOWN_ERROR',
    statusCode: number = 500,
    details?: Record<string, unknown>,
    requestId?: string
  ) {
    super(message)
    this.requestId = requestId
    this.name = 'ApiClientError'
    this.code = code
    this.statusCode = statusCode
    this.details = details

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ApiClientError)
    }
  }

  /**
   * Convert to ApiError format
   */
  toApiError(): ApiError {
    return {
      code: this.code,
      message: this.message,
      statusCode: this.statusCode,
      details: this.details,
      requestId: this.requestId,
    }
  }

  /**
   * Check if error is specific type
   */
  is(code: string): boolean {
    return this.code === code
  }

  /**
   * Check if error is authentication error
   */
  isAuthError(): boolean {
    return (
      this.statusCode === 401 ||
      this.code === 'UNAUTHORIZED' ||
      this.code === 'TOKEN_EXPIRED' ||
      this.code === 'INVALID_TOKEN'
    )
  }

  /**
   * Check if error is validation error
   */
  isValidationError(): boolean {
    return this.statusCode === 422 || this.code === 'VALIDATION_ERROR'
  }

  /**
   * Check if error is not found
   */
  isNotFoundError(): boolean {
    return this.statusCode === 404 || this.code === 'NOT_FOUND'
  }

  /**
   * Check if error is server error
   */
  isServerError(): boolean {
    return this.statusCode >= 500
  }

  /**
   * Check if error is client error
   */
  isClientError(): boolean {
    return this.statusCode >= 400 && this.statusCode < 500
  }
}

// ============================================
// ERROR HANDLER
// ============================================

/** The HTTP status an error carries, if any (statusCode or status). */
function statusOf(error: unknown): number | undefined {
  if (error && typeof error === 'object') {
    const e = error as { statusCode?: unknown; status?: unknown }
    if (typeof e.statusCode === 'number') return e.statusCode
    if (typeof e.status === 'number') return e.status
  }
  return undefined
}

/**
 * A server error, rate limit or network failure: usually transient (the API
 * restarting during a deploy) and retried by SWR.
 */
/**
 * A write refused because the module became unavailable for the organization recently:
 * it is read-only (view and export) until its grace ends.
 */
export function isReadOnlyModuleError(error: ApiClientError): boolean {
  return error.code === 'MODULE_NOT_ENABLED' && error.details?.reason === 'read_only_grace'
}

export function isTransientApiError(error: ApiClientError): boolean {
  const s = error.statusCode
  return !s || s >= 500 || s === 429 || error.code === 'NETWORK_ERROR' || error.code === 'TIMEOUT'
}

/**
 * Handle API errors with user-friendly messages
 *
 * @param error - Error from API call
 * @param options - Handler options
 * @returns Processed error
 *
 * @example
 * ```typescript
 * try {
 *   await apiClient('/api/users')
 * } catch (error) {
 *   handleApiError(error, {
 *     showToast: true,
 *     logError: true
 *   })
 * }
 * ```
 */
export function handleApiError(
  error: unknown,
  options: {
    /**
     * Show toast notification
     */
    showToast?: boolean

    /**
     * Log error to console
     */
    logError?: boolean

    /**
     * Custom error messages by error code
     */
    customMessages?: Record<string, string>

    /**
     * Callback on error
     */
    onError?: (error: ApiClientError) => void

    /**
     * Fallback message if no specific message found
     */
    fallbackMessage?: string
  } = {}
): ApiClientError {
  const {
    showToast = true,
    logError = true,
    customMessages = {},
    onError,
    fallbackMessage = 'An unexpected error occurred',
  } = options

  // Convert to ApiClientError if needed, keeping the HTTP status when the
  // error carries one (fetch wrappers use statusCode or status).
  const apiError =
    error instanceof ApiClientError
      ? error
      : new ApiClientError(
          error instanceof Error ? error.message : fallbackMessage,
          'UNKNOWN_ERROR',
          statusOf(error)
        )

  // Get user-friendly message
  const message = getUserFriendlyMessage(apiError, customMessages, fallbackMessage)

  // Log error if enabled: one readable line (the dev overlay printed the
  // object as "{}"). A 5xx/429 or network failure is usually transient (the
  // API restarting during a deploy) and SWR retries it, so it is a warning;
  // anything else is an error worth the overlay.
  if (logError) {
    const line = `[API Error] ${apiError.statusCode || 'network'} ${apiError.code}: ${apiError.message}`
    if (isTransientApiError(apiError)) {
      devLog.warn(`${line} (will retry)`)
    } else {
      devLog.error(line, apiError.details ?? '')
    }
  }

  // Show toast if enabled
  // Defense-in-depth: a disabled module returns 403 MODULE_NOT_ENABLED. This is
  // an expected empty state, not an error the user can act on — features for a
  // disabled module should already be hidden and their fetches skipped, but if
  // one slips through we swallow the toast (still logged above). Real RBAC
  // denials (FORBIDDEN) keep their toast.
  // IP allowlist blocks share one de-duplicated toast with the API client.
  if (showToast && apiError.code === IP_NOT_ALLOWED_CODE) {
    notifyIpNotAllowed()
  } else if (showToast && isReadOnlyModuleError(apiError)) {
    // Unlike a module that is off (its pages are hidden), a module in
    // read-only grace shows its pages, so a refused save must say why.
    toast.error('Read-only', { description: message })
  } else if (showToast && apiError.code !== 'MODULE_NOT_ENABLED') {
    // Different toast types based on error
    if (apiError.code === APPROVAL_REQUIRED_CODE) {
      // The server message says who can approve and what to do instead.
      toast.error('Approval required', {
        description: message,
      })
    } else if (apiError.code === 'FORBIDDEN' && describePermissionDenied(apiError.details)) {
      // The refusal named the missing permission or role.
      toast.error('Permission needed', {
        description: message,
      })
    } else if (apiError.isAuthError()) {
      toast.error('Authentication Error', {
        description: message,
      })
    } else if (apiError.isValidationError()) {
      toast.error('Validation Error', {
        description: message,
      })
    } else if (apiError.isNotFoundError()) {
      toast.error('Not Found', {
        description: message,
      })
    } else if (apiError.isServerError()) {
      toast.error('Server Error', {
        description: message,
      })
    } else {
      toast.error('Error', {
        description: message,
      })
    }
  }

  // Call custom error handler
  if (onError) {
    onError(apiError)
  }

  return apiError
}

// ============================================
// USER-FRIENDLY MESSAGES
// ============================================

/**
 * Get user-friendly error message: a caller's message for the code first,
 * then the shared mapper (error-message.ts).
 */
function getUserFriendlyMessage(
  error: ApiClientError,
  customMessages: Record<string, string>,
  fallback: string
): string {
  if (customMessages[error.code]) {
    return customMessages[error.code]
  }
  if (error.code === IP_NOT_ALLOWED_CODE) return IP_NOT_ALLOWED_MESSAGE
  return apiErrorMessage(error, fallback)
}

// ============================================
// RETRY UTILITIES
// ============================================

/**
 * Check if error is retryable
 */
export function isRetryableError(error: ApiClientError): boolean {
  // Network errors are retryable
  if (error.code === 'NETWORK_ERROR' || error.code === 'TIMEOUT') {
    return true
  }

  // Server errors (5xx) are retryable
  if (error.statusCode >= 500) {
    return true
  }

  // Rate limit errors might be retryable after delay
  if (error.statusCode === 429) {
    return true
  }

  return false
}

/**
 * Get retry delay for error (in milliseconds)
 */
export function getRetryDelay(error: ApiClientError, attempt: number): number {
  // Rate limit - use longer delay
  if (error.statusCode === 429) {
    return 5000 * attempt // 5s, 10s, 15s, etc.
  }

  // Network/timeout - exponential backoff
  if (error.code === 'NETWORK_ERROR' || error.code === 'TIMEOUT') {
    return Math.min(1000 * Math.pow(2, attempt), 10000) // Max 10s
  }

  // Server errors - linear backoff
  if (error.statusCode >= 500) {
    return 2000 * attempt // 2s, 4s, 6s, etc.
  }

  return 1000 // Default 1s
}

/**
 * Retry a function with exponential backoff
 *
 * @example
 * ```typescript
 * const data = await retryWithBackoff(
 *   () => apiClient('/api/users'),
 *   { maxRetries: 3 }
 * )
 * ```
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  options: {
    maxRetries?: number
    onRetry?: (error: ApiClientError, attempt: number) => void
  } = {}
): Promise<T> {
  const { maxRetries = 3, onRetry } = options

  let lastError: ApiClientError | undefined

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn()
    } catch (error) {
      const apiError = error instanceof ApiClientError ? error : new ApiClientError('Unknown error')

      lastError = apiError

      // Don't retry if not retryable or max retries reached
      if (!isRetryableError(apiError) || attempt === maxRetries) {
        throw apiError
      }

      // Call retry callback
      if (onRetry) {
        onRetry(apiError, attempt + 1)
      }

      // Wait before retrying
      const delay = getRetryDelay(apiError, attempt + 1)
      await new Promise((resolve) => setTimeout(resolve, delay))
    }
  }

  throw lastError
}

// ============================================
// VALIDATION HELPERS
// ============================================

/**
 * Extract validation errors from API error
 */
export function extractValidationErrors(error: ApiClientError): Record<string, string> | null {
  if (!error.isValidationError() || !error.details) {
    return null
  }

  // Check if details has errors array (common format)
  if (Array.isArray(error.details.errors)) {
    const errors: Record<string, string> = {}
    error.details.errors.forEach((err: { field: string; message: string }) => {
      if (err.field && err.message) {
        errors[err.field] = err.message
      }
    })
    return errors
  }

  // Check if details is already a field-message map
  if (typeof error.details === 'object') {
    return error.details as Record<string, string>
  }

  return null
}

// ============================================
// ERROR MESSAGE EXTRACTION
// ============================================

/**
 * The sentence to show for any thrown value: the console's words for a known
 * API code, a safe server sentence for a generic one, else `fallback` (the
 * caller's "Could not …") with a request reference on unexpected failures.
 * Never an id, a stack or the raw text of a JavaScript error
 * (`error-message.ts`).
 */
export function getErrorMessage(error: unknown, fallback?: string): string {
  return apiErrorMessage(error, fallback)
}
