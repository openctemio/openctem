import { describeCode, safeText, type Translate } from '@/lib/api/error-message'
import { formatAbsoluteTime } from '@/lib/format-metric'

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

/**
 * The status code the API stores when a member turns a connection off
 * (server: integration.StatusCodeDisabledByUser). Its English message is
 * "Disabled by user at <RFC 3339 time>"; rows written before the code
 * existed carry the same message with no code.
 */
export const DISABLED_BY_USER_CODE = 'INTEGRATION_DISABLED_BY_USER'
const DISABLED_BY_USER_PREFIX = 'Disabled by user at '

/** When a member turned the connection off, from its status, else null. */
export function disabledByUserAt(
  status: { status?: string; status_code?: string; status_message?: string } | undefined
): Date | null {
  if (!status || status.status !== 'disabled') return null
  const msg = status.status_message ?? ''
  if (status.status_code !== DISABLED_BY_USER_CODE && !msg.startsWith(DISABLED_BY_USER_PREFIX))
    return null
  const d = new Date(msg.slice(DISABLED_BY_USER_PREFIX.length).trim())
  return Number.isNaN(d.getTime()) ? new Date(NaN) : d
}

/**
 * The one line under a connection's name or status in a list (hub, SCM,
 * notifications, SIEM, ticketing): why it failed, in the reader's language,
 * or when it was turned off, with the time in the reader's locale. Never the
 * stored English sentence when a code says what it means.
 */
export function connectionNote(
  i:
    | {
        status?: string
        status_code?: string
        status_message?: string
        sync_error?: string
      }
    | undefined,
  t: Translate,
  locale: string
): { text: string; tone: 'error' | 'muted' } | null {
  if (!i) return null
  const off = disabledByUserAt(i)
  if (off) {
    const when = Number.isNaN(off.getTime()) ? '' : formatAbsoluteTime(off, locale)
    return {
      text: when
        ? t('integrationsHub.note.disabledAt', 'Turned off on {date}', { date: when })
        : t('integrationsHub.note.disabled', 'Turned off by a member'),
      tone: 'muted',
    }
  }
  if (i.status !== 'error' && !i.sync_error) return null
  const p = connectionProblem(
    { status_code: i.status_code, status_message: i.status_message || i.sync_error },
    t,
    t(
      'errors.INTEGRATION_TEST_FAILED',
      'The connection test failed. Check the settings and test again.'
    )
  )
  return { text: p.message, tone: 'error' }
}
