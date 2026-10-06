/**
 * Step-up re-authentication (API docs: architecture/step-up-reauth.md).
 *
 * Sensitive API routes answer `403 {code: "STEP_UP_REQUIRED"}` when the
 * session has not signed in or re-authenticated in the last 10 minutes. The
 * shared API client (`apiClient`) then calls `requestStepUp()`, which opens
 * the one re-authentication dialog (`StepUpDialogHost`, mounted once in the
 * app providers). When the user confirms, the client retries the original
 * request once; when they cancel, the original error is thrown.
 *
 * The window itself lives on the server, on the session. Nothing here stores
 * a flag the server trusts.
 */

export const STEP_UP_REQUIRED_CODE = 'STEP_UP_REQUIRED'
export const STEP_UP_UNAVAILABLE_CODE = 'STEP_UP_UNAVAILABLE'
export const STEP_UP_FAILED_CODE = 'STEP_UP_FAILED'

export const STEP_UP_ENDPOINT = '/api/v1/auth/step-up'

/** What the account must present: GET /api/v1/auth/step-up `method`. */
export type StepUpMethod = 'totp' | 'password' | 'fresh_sign_in'

export interface StepUpState {
  method: StepUpMethod
  valid_until?: string
  window_seconds: number
}

/** POST /api/v1/auth/step-up body: one of the two. */
export interface StepUpProof {
  totp?: string
  password?: string
}

export function isStepUpRequired(
  err: { statusCode?: number; code?: string } | null | undefined
): boolean {
  return !!err && err.statusCode === 403 && err.code === STEP_UP_REQUIRED_CODE
}

/**
 * Opens the dialog and resolves true once the user re-authenticated, false
 * when they cancelled.
 */
export type StepUpHandler = () => Promise<boolean>

let handler: StepUpHandler | null = null
let inFlight: Promise<boolean> | null = null

/**
 * Registers the dialog that answers step-up prompts. Returns the function
 * that unregisters it (only if it is still the registered one).
 */
export function registerStepUpHandler(h: StepUpHandler): () => void {
  handler = h
  return () => {
    if (handler === h) handler = null
  }
}

/**
 * Asks the user to re-authenticate. Concurrent callers share one prompt.
 * Without a mounted dialog (server rendering, tests) it resolves false, and
 * the caller surfaces the original STEP_UP_REQUIRED error.
 */
export function requestStepUp(): Promise<boolean> {
  if (typeof window === 'undefined' || !handler) return Promise.resolve(false)
  if (!inFlight) {
    const h = handler
    inFlight = h()
      .catch(() => false)
      .finally(() => {
        inFlight = null
      })
  }
  return inFlight
}
