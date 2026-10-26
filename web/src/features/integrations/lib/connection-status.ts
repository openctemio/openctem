import { describeCode, safeText, type Translate } from '@/lib/api/error-message'

/** Codes whose fix is entering the API token again. */
const TOKEN_CODES = new Set([
  'INTEGRATION_NO_CREDENTIALS',
  'INTEGRATION_CREDENTIALS_UNREADABLE',
  'INTEGRATION_AUTH_FAILED',
])

/** What to show for a connection that failed its test. */
export interface ConnectionProblem {
  message: string
  /** Label of the inline fix ("Add API token"), when there is one. */
  actionLabel?: string
  /** The fix is entering the API token again. */
  needsToken: boolean
}

/**
 * The words for a failed connection: from its status code when known, else
 * its stored sentence when that is safe to show, else the caller's sentence.
 * Never the raw stored text (older rows can hold an upstream error).
 */
export function connectionProblem(
  status: { status_code?: string; status_message?: string } | undefined,
  t: Translate,
  fallback: string
): ConnectionProblem {
  const code = status?.status_code
  const known = describeCode(code, t)
  if (known) {
    return {
      message: known.message,
      actionLabel: known.actionLabel,
      needsToken: TOKEN_CODES.has(code ?? ''),
    }
  }
  return { message: safeText(status?.status_message, fallback), needsToken: false }
}
