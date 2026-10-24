/**
 * The one path from a failed request to the words a person reads
 * (research 258, api docs/architecture/error-responses.md).
 *
 * - A registered API code is worded by the console: `errors.<CODE>` in the
 *   en and vi dictionaries, with `details.params` interpolated and an
 *   optional `errors.<CODE>.action` label for the inline fix.
 * - A generic code (BAD_REQUEST, NOT_FOUND, ...) keeps the server's more
 *   specific sentence when it is safe to show.
 * - An unexpected failure (5xx, network, a JavaScript error) shows the
 *   caller's "Could not …" sentence and a short request reference; never the
 *   raw text of the error.
 * - Nothing that looks like an entity id, SQL, a stack or an internal host
 *   is ever shown, whatever the source.
 */
import { toast } from 'sonner'

import { getDictionary, translate, type TranslateVars } from '@/lib/i18n'

import { ApiClientError, APPROVAL_REQUIRED_CODE, isReadOnlyModuleError } from './error-handler'
import { describePermissionDenied } from './permission-denied'

export type Translate = (key: string, fallback?: string, vars?: TranslateVars) => string

/** What to show for one failure. */
export interface ErrorDescription {
  /** The sentence to show (translated when the code is known). */
  message: string
  /** The API code, when there is one. */
  code?: string
  /** The label of the inline fix for this code ("Add API token"), if any. */
  actionLabel?: string
  /** Short request reference for support, on unexpected failures. */
  reference?: string
  /** The full request id (for a copy button). */
  requestId?: string
}

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i

// Mirrors api pkg/apierror/safe.go technicalRe: text only the server should see.
const TECHNICAL = new RegExp(
  [
    'sqlstate',
    '\\bpq: ',
    '\\bpgx\\b',
    'pgconn',
    '\\bsql: ',
    'duplicate key value',
    'violates [a-z -]*constraint',
    'null value in column',
    '\\brelation "',
    'syntax error at or near',
    '\\bdial (tcp|udp)\\b',
    'no such host',
    'connection refused',
    'connection reset',
    'i/o timeout',
    'context deadline exceeded',
    'context canceled',
    '\\bx509: ',
    '\\btls: ',
    'unexpected eof',
    'runtime error',
    'nil pointer',
    'goroutine \\d',
    '\\.go:\\d+',
    'json: cannot unmarshal',
    'go struct field',
    '<nil>',
    '%!',
    '\\bat [\\w.$<>]+ \\(.*:\\d+:\\d+\\)',
    'cannot read propert',
    'is not a function',
    'unexpected token',
    '(^|[\\s"\'(=])/(home|var|tmp|etc|usr|app|opt|root|proc|srv)/',
    '\\blocalhost:\\d+',
    '\\b127\\.0\\.0\\.1\\b',
    '\\.svc\\.cluster\\.local',
    '<html',
    '<!doctype',
    '\\{"[a-z_]+"\\s*:',
  ].join('|'),
  'i'
)

const MAX_MESSAGE = 300

/** A message that is fit to show a person: no id, no internal text, short. */
export function isSafeMessage(msg: unknown): msg is string {
  return (
    typeof msg === 'string' &&
    msg.trim() !== '' &&
    msg.length <= MAX_MESSAGE &&
    !UUID.test(msg) &&
    !TECHNICAL.test(msg)
  )
}

/** Codes too broad to beat the server's own (safe) sentence. */
const GENERIC_CODES = new Set([
  'BAD_REQUEST',
  'CONFLICT',
  'NOT_FOUND',
  'VALIDATION_FAILED',
  'VALIDATION_ERROR',
  'UNPROCESSABLE_ENTITY',
  'UNKNOWN_ERROR',
])

/** Failures whose cause the person cannot act on: reference for support. */
function isUnexpected(err: ApiClientError): boolean {
  return (
    err.statusCode >= 500 ||
    err.statusCode === 0 ||
    err.code === 'UNKNOWN_ERROR' ||
    err.code === 'NETWORK_ERROR' ||
    err.code === 'TIMEOUT'
  )
}

/** The first characters of a request id: enough to find it in the log. */
export function shortReference(requestId: string | undefined): string | undefined {
  if (!requestId) return undefined
  const clean = requestId.replace(/[^A-Za-z0-9._-]/g, '')
  return clean ? clean.slice(0, 8) : undefined
}

function safeParams(details: unknown): TranslateVars | undefined {
  const params = (details as { params?: unknown } | undefined)?.params
  if (!params || typeof params !== 'object') return undefined
  const out: TranslateVars = {}
  for (const [k, v] of Object.entries(params as Record<string, unknown>)) {
    if ((typeof v === 'string' && isSafeMessage(v)) || typeof v === 'number') out[k] = v
  }
  return out
}

function has(t: Translate, key: string): boolean {
  // translate() returns the key itself when nothing matches.
  return t(key, '\u0000') !== '\u0000'
}

/**
 * The console's words for an API code (also for a code stored on a row,
 * such as an integration's status_code). Undefined for an unknown code.
 */
export function describeCode(
  code: string | undefined | null,
  t: Translate,
  params?: TranslateVars
): ErrorDescription | undefined {
  if (!code || !/^[A-Z][A-Z0-9_]*$/.test(code)) return undefined
  const key = `errors.${code}`
  if (!has(t, key)) return undefined
  const actionKey = `${key}.action`
  return {
    code,
    message: t(key, undefined, params),
    actionLabel: has(t, actionKey) ? t(actionKey) : undefined,
  }
}

/** Validation reasons ({field, message}[]) as one sentence, safe parts only. */
function validationReasons(details: unknown): string | undefined {
  const list = Array.isArray(details)
    ? details
    : Array.isArray((details as { errors?: unknown } | undefined)?.errors)
      ? (details as { errors: unknown[] }).errors
      : undefined
  if (!list) return undefined
  const reasons = (list as { field?: unknown; message?: unknown }[])
    .filter((d) => d && isSafeMessage(d.message))
    .map((d) =>
      typeof d.field === 'string' && d.field && !UUID.test(d.field)
        ? `${d.field} ${d.message as string}`
        : (d.message as string)
    )
  return reasons.length > 0 ? reasons.join('. ') : undefined
}

/**
 * Describe any thrown value. `fallback` is the caller's "Could not …"
 * sentence, used whenever the cause is not something the person can act on.
 */
export function describeApiError(err: unknown, t: Translate, fallback?: string): ErrorDescription {
  const generic = fallback || t('errors.generic', 'Could not complete this. Try again.')
  if (err instanceof ApiClientError) {
    const requestId = err.requestId
    if (err.code === 'FORBIDDEN') {
      const why = describePermissionDenied(err.details)
      if (why) return { message: why, code: err.code }
    }
    // These carry an actionable, server-written sentence.
    if (
      (err.code === APPROVAL_REQUIRED_CODE || isReadOnlyModuleError(err)) &&
      isSafeMessage(err.message)
    ) {
      return { message: err.message, code: err.code }
    }
    const reasons = validationReasons(err.details)
    if (reasons) return { message: reasons, code: err.code }
    if (isUnexpected(err)) {
      const known = err.code !== 'UNKNOWN_ERROR' ? describeCode(err.code, t) : undefined
      const network = err.code === 'NETWORK_ERROR' || err.statusCode === 0
      return {
        message: network ? t('errors.network') : generic,
        code: known?.code ?? err.code,
        reference: shortReference(requestId),
        requestId,
      }
    }
    const known = describeCode(err.code, t, safeParams(err.details))
    if (known && !GENERIC_CODES.has(err.code)) return known
    if (isSafeMessage(err.message)) return { message: err.message, code: err.code }
    if (known) return known
    return { message: generic, code: err.code, reference: shortReference(requestId), requestId }
  }
  // A plain Error a caller threw with its own sentence is shown; a runtime
  // error (TypeError, "Failed to fetch") is not.
  if (err instanceof Error) {
    if (err.name === 'Error' && isSafeMessage(err.message)) return { message: err.message }
    return { message: generic }
  }
  if (isSafeMessage(err)) return { message: err }
  return { message: generic }
}

/** The description as one line, with the reference when there is one. */
export function errorText(d: ErrorDescription, t: Translate): string {
  return d.reference
    ? `${d.message} ${t('errors.reference', undefined, { id: d.reference })}`
    : d.message
}

/** Translator for code that has no React context: the page's language. */
function documentTranslate(): Translate {
  const lang = typeof document !== 'undefined' ? document.documentElement.lang : undefined
  const dict = getDictionary(lang || undefined)
  return (key, fallback, vars) => translate(dict, key, fallback, vars)
}

/** One-line message outside React (getErrorMessage uses it). */
export function apiErrorMessage(
  err: unknown,
  fallback?: string,
  t: Translate = documentTranslate()
): string {
  return errorText(describeApiError(err, t, fallback), t)
}

/**
 * Toast a failed action: the sentence, and the reference as the description
 * on unexpected failures. The same failure twice replaces the first toast
 * instead of stacking. No action buttons in toasts: a fix belongs where the
 * thing is (a row, a form).
 */
export function toastError(
  err: unknown,
  fallback?: string,
  t: Translate = documentTranslate()
): ErrorDescription {
  const d = describeApiError(err, t, fallback)
  toast.error(d.message, {
    id: `api-error:${d.code ?? ''}:${d.message}`,
    description: d.reference ? t('errors.reference', undefined, { id: d.reference }) : undefined,
  })
  return d
}

/**
 * A server-written sentence (a result's `error`, a stored status text) when
 * it is safe to show, else the caller's own sentence.
 */
export function safeText(msg: unknown, fallback: string): string {
  return isSafeMessage(msg) ? msg : fallback
}

/**
 * Words for an API code outside React (the page's language), else the safe
 * server sentence, else the caller's sentence.
 */
export function codeText(
  code: string | undefined,
  serverMessage: unknown,
  fallback: string
): string {
  return describeCode(code, documentTranslate())?.message ?? safeText(serverMessage, fallback)
}
