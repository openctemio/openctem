/**
 * Fetch client for the platform admin console. Requests go to the dedicated
 * /api/v1/admin proxy, which forwards only the admin_* cookies. Writes carry
 * the double-submit CSRF header: the console session's token, which the API
 * returns in the body of the sign-in and validate responses and this module
 * keeps in memory only (no console secret is ever readable in a cookie: on a
 * second port of the tenant host the two sites share the host's cookies).
 * Before a session exists, the sign-in steps echo the page's csrf_token (as
 * the global fetch wrapper, src/lib/csrf-client.ts, would).
 */

export const ADMIN_API = '/api/v1/admin'
/** The page CSRF cookie, echoed only by the sign-in steps before a session exists. */
const PAGE_CSRF_COOKIE = 'csrf_token'

/** The console session's CSRF token, in memory only. */
let sessionCsrf: string | null = null

/** Replaces (or, with null, forgets) the console session's CSRF token. */
export function setAdminCsrfToken(token: string | null) {
  sessionCsrf = token
}

/** A csrf_token in a response: top level (validate, TOTP step) or under `admin` (IdP callback). */
function csrfFrom(data: unknown): string | undefined {
  if (!data || typeof data !== 'object') return undefined
  const top = (data as { csrf_token?: unknown }).csrf_token
  if (typeof top === 'string' && top) return top
  const nested = (data as { admin?: { csrf_token?: unknown } }).admin?.csrf_token
  return typeof nested === 'string' && nested ? nested : undefined
}

/** Responses that end the console session: the token goes with it. */
const SESSION_ENDING = new Set(['/auth/logout', '/auth/password'])

/**
 * Protected console actions (identity, privilege and platform-trust changes)
 * need a fresh confirmation: an authenticator code in this header, or a
 * security-key step-up that opens the session's five-minute window (the action
 * is then retried without a code). The API answers ADMIN_STEP_UP_REQUIRED
 * (401, route level), STEP_UP_REQUIRED (401, actions whose form carries the
 * code) or WEBAUTHN_REQUIRED (403, only a security key is accepted), and the
 * console asks and retries.
 */
export const ADMIN_STEP_UP_HEADER = 'X-Admin-Step-Up'
export const ADMIN_STEP_UP_REQUIRED = 'ADMIN_STEP_UP_REQUIRED'
export const ADMIN_FORM_STEP_UP_REQUIRED = 'STEP_UP_REQUIRED'
export const WEBAUTHN_REQUIRED = 'WEBAUTHN_REQUIRED'
export const FACTOR_ENROLLMENT_REQUIRED = 'FACTOR_ENROLLMENT_REQUIRED'
/** Confirmations asked for one action before giving up. */
const STEP_UP_ATTEMPTS = 3

/** What the step-up dialog is asked for. */
export interface AdminStepUpRequest {
  /** Only a security key is accepted (403 WEBAUTHN_REQUIRED). */
  keyOnly: boolean
  /**
   * The code belongs in the form (STEP_UP_REQUIRED): the dialog offers only a
   * security key, and gives up at once when the administrator has none.
   */
  formCode: boolean
  /** The API's refusal of the previous code, if any. */
  problem?: string
}

/** A code to send in the header, or a security-key step-up that already passed. */
export type AdminStepUpAnswer = { kind: 'code'; code: string } | { kind: 'key' }

/** Asks the administrator to confirm. Resolves to null when they cancel. */
export type AdminStepUpPrompt = (request: AdminStepUpRequest) => Promise<AdminStepUpAnswer | null>

let stepUpPrompt: AdminStepUpPrompt | null = null

/** Registers the console's step-up dialog (one per console shell). */
export function setAdminStepUpPrompt(prompt: AdminStepUpPrompt | null) {
  stepUpPrompt = prompt
}

let enrollmentListener: (() => void) | null = null

/**
 * Registers the shell's reaction to 403 FACTOR_ENROLLMENT_REQUIRED: the
 * console requires security keys and this administrator has not registered
 * them, so only the enrollment page can work.
 */
export function setAdminEnrollmentListener(listener: (() => void) | null) {
  enrollmentListener = listener
}

/**
 * Reads the console makes on its own (the periodic refresh of an open page)
 * carry this header, so the API does not count them as activity and an
 * unattended tab still reaches the 15-minute idle timeout. A read counts as
 * background when the page is hidden or nobody pressed a key, clicked or
 * touched it for a minute. It never grants anything; writes never carry it.
 */
export const ADMIN_BACKGROUND_HEADER = 'X-Admin-Background'
/** How long after the last key, click or touch a read still counts as the administrator's. */
export const INTERACTION_WINDOW_MS = 60_000

let lastInteraction = Date.now()

/** Records that the administrator used the page now (tests call it directly). */
export function noteAdminInteraction(at: number = Date.now()) {
  lastInteraction = at
}

if (typeof window !== 'undefined') {
  const note = () => noteAdminInteraction()
  for (const type of ['pointerdown', 'keydown', 'touchstart'] as const) {
    window.addEventListener(type, note, { capture: true, passive: true })
  }
}

/** Whether a read now is the console's own, not the administrator's. */
export function isBackgroundRead(now: number = Date.now()): boolean {
  if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return true
  return now - lastInteraction > INTERACTION_WINDOW_MS
}

export class AdminApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
    /** The API's structured detail for the refusal, when it sends one. */
    readonly details?: unknown
  ) {
    super(message)
    this.name = 'AdminApiError'
  }
}

function readCookie(name: string): string | undefined {
  if (typeof document === 'undefined') return undefined
  const prefix = `${name}=`
  for (const part of document.cookie.split(';')) {
    const c = part.trim()
    if (c.startsWith(prefix)) return decodeURIComponent(c.slice(prefix.length))
  }
  return undefined
}

export interface AdminFetchInit {
  method?: string
  body?: unknown
  /** A code the caller already asked for (sent as the step-up header). */
  stepUpCode?: string
}

/**
 * A form that already asked for a fresh code sends it in `totp_code`; it goes
 * in the step-up header too, so the route confirms it once and no second
 * prompt appears.
 */
function bodyStepUpCode(body: unknown): string | undefined {
  if (typeof FormData !== 'undefined' && body instanceof FormData) {
    const v = body.get('totp_code')
    return typeof v === 'string' && v ? v : undefined
  }
  if (body && typeof body === 'object' && 'totp_code' in body) {
    const v = (body as { totp_code?: unknown }).totp_code
    return typeof v === 'string' && v ? v : undefined
  }
  return undefined
}

/** Second steps of a sign-in: a refusal there is the answer, not a step-up. */
const SIGN_IN_PATHS = new Set(['/auth/session', '/auth/mfa', '/auth/recovery'])

/** The body without the form's code, for a retry inside a key step-up window. */
function withoutBodyCode(body: unknown): unknown {
  if (typeof FormData !== 'undefined' && body instanceof FormData) {
    if (!body.has('totp_code')) return body
    const copy = new FormData()
    body.forEach((v, k) => {
      if (k !== 'totp_code') copy.append(k, v)
    })
    return copy
  }
  if (body && typeof body === 'object' && !Array.isArray(body) && 'totp_code' in body) {
    const { totp_code: _drop, ...rest } = body as Record<string, unknown>
    void _drop
    return rest
  }
  return body
}

/** The step-up the refusal asks for, or null when it is not one. */
function stepUpRequest(err: unknown, sentCode: boolean): AdminStepUpRequest | null {
  if (!(err instanceof AdminApiError)) return null
  if (err.code === ADMIN_STEP_UP_REQUIRED)
    return { keyOnly: false, formCode: false, problem: sentCode ? err.message : undefined }
  if (err.code === WEBAUTHN_REQUIRED && err.status === 403)
    return { keyOnly: true, formCode: false }
  if (err.code === ADMIN_FORM_STEP_UP_REQUIRED && err.status === 401 && !sentCode)
    return { keyOnly: true, formCode: true }
  return null
}

export async function adminFetch<T>(path: string, init: AdminFetchInit = {}): Promise<T> {
  let request = init
  let code = init.stepUpCode ?? bodyStepUpCode(init.body)
  // The sign-in steps and the key step-up itself never ask for a step-up.
  const canPrompt =
    !SIGN_IN_PATHS.has(path) &&
    !path.startsWith('/auth/step-up/') &&
    !path.startsWith('/auth/webauthn/session')
  for (let attempt = 1; ; attempt++) {
    try {
      return await adminRequest<T>(path, request, code)
    } catch (err) {
      const prompt = stepUpPrompt
      const ask = canPrompt && attempt <= STEP_UP_ATTEMPTS ? stepUpRequest(err, !!code) : null
      if (!ask || !prompt) throw err
      const answer = await prompt(ask)
      if (!answer) throw err
      if (answer.kind === 'code') {
        code = answer.code
      } else {
        // The key opened this session's step-up window: the same request,
        // without any code, now passes.
        code = undefined
        request = { ...request, stepUpCode: undefined, body: withoutBodyCode(request.body) }
      }
    }
  }
}

async function adminRequest<T>(
  path: string,
  init: AdminFetchInit,
  stepUpCode?: string
): Promise<T> {
  const method = init.method ?? 'GET'
  const headers: Record<string, string> = { Accept: 'application/json' }
  // A FormData body (a file upload) sets its own multipart content type.
  const isForm = typeof FormData !== 'undefined' && init.body instanceof FormData
  if (init.body !== undefined && !isForm) headers['Content-Type'] = 'application/json'
  if (method !== 'GET' && method !== 'HEAD') {
    const csrf = sessionCsrf ?? readCookie(PAGE_CSRF_COOKIE)
    if (csrf) headers['X-CSRF-Token'] = csrf
    if (stepUpCode) headers[ADMIN_STEP_UP_HEADER] = stepUpCode
  }
  if ((method === 'GET' || method === 'HEAD') && isBackgroundRead()) {
    headers[ADMIN_BACKGROUND_HEADER] = '1'
  }

  const res = await fetch(`${ADMIN_API}${path}`, {
    method,
    headers,
    body:
      init.body === undefined
        ? undefined
        : isForm
          ? (init.body as FormData)
          : JSON.stringify(init.body),
    credentials: 'same-origin',
    cache: 'no-store',
  })

  if (SESSION_ENDING.has(path) && res.ok) sessionCsrf = null
  if (res.status === 401 && path === '/auth/validate') sessionCsrf = null
  if (res.status === 204) return undefined as T
  const text = await res.text()
  let data: unknown = undefined
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = undefined
    }
  }
  if (!res.ok) {
    const body = (data ?? {}) as {
      message?: string
      error?: string
      code?: string
      details?: unknown
    }
    if (res.status === 403 && body.code === FACTOR_ENROLLMENT_REQUIRED) enrollmentListener?.()
    throw new AdminApiError(
      body.message || body.error || res.statusText,
      res.status,
      body.code,
      body.details
    )
  }
  const token = csrfFrom(data)
  if (token) sessionCsrf = token
  return data as T
}

/** SWR fetcher for GET paths under /api/v1/admin. */
export const adminFetcher = <T>(path: string) => adminFetch<T>(path)
