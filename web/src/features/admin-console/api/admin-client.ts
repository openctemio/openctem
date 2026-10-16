/**
 * Fetch client for the platform admin console. Requests go to the dedicated
 * /api/v1/admin proxy, which forwards only the admin_* cookies. Writes carry
 * the double-submit CSRF header from the readable admin_csrf_page cookie (distinct
 * from the tenant csrf_token, so both shells can be open in one browser).
 */

export const ADMIN_API = '/api/v1/admin'
/** The readable copy of the console's CSRF token, scoped to /admin pages. */
const ADMIN_CSRF_COOKIE = 'admin_csrf_page'

/**
 * Protected console actions (identity, privilege and platform-trust changes)
 * need a fresh authenticator code in this header, unless the console session
 * confirmed one in the last few minutes. The API answers
 * ADMIN_STEP_UP_REQUIRED (401) and the console asks for a code and retries.
 */
export const ADMIN_STEP_UP_HEADER = 'X-Admin-Step-Up'
export const ADMIN_STEP_UP_REQUIRED = 'ADMIN_STEP_UP_REQUIRED'
/** Codes asked for one action before giving up. */
const STEP_UP_ATTEMPTS = 3

/**
 * Asks the administrator for a fresh code. `problem` is the API's refusal of
 * the previous code, if any. Resolves to null when the administrator cancels.
 */
export type AdminStepUpPrompt = (problem?: string) => Promise<string | null>

let stepUpPrompt: AdminStepUpPrompt | null = null

/** Registers the console's step-up dialog (one per console shell). */
export function setAdminStepUpPrompt(prompt: AdminStepUpPrompt | null) {
  stepUpPrompt = prompt
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

export async function adminFetch<T>(path: string, init: AdminFetchInit = {}): Promise<T> {
  let code = init.stepUpCode ?? bodyStepUpCode(init.body)
  for (let attempt = 1; ; attempt++) {
    try {
      return await adminRequest<T>(path, init, code)
    } catch (err) {
      const prompt = stepUpPrompt
      const retry =
        err instanceof AdminApiError &&
        err.code === ADMIN_STEP_UP_REQUIRED &&
        prompt !== null &&
        attempt <= STEP_UP_ATTEMPTS
      if (!retry) throw err
      // The first refusal only means "confirm"; a later one names the problem
      // with the code that was typed (wrong or already used).
      const next = await prompt(code ? err.message : undefined)
      if (!next) throw err
      code = next
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
    const csrf = readCookie(ADMIN_CSRF_COOKIE)
    if (csrf) headers['X-CSRF-Token'] = csrf
    if (stepUpCode) headers[ADMIN_STEP_UP_HEADER] = stepUpCode
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
    throw new AdminApiError(
      body.message || body.error || res.statusText,
      res.status,
      body.code,
      body.details
    )
  }
  return data as T
}

/** SWR fetcher for GET paths under /api/v1/admin. */
export const adminFetcher = <T>(path: string) => adminFetch<T>(path)
