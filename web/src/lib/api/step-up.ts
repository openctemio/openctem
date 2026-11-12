/**
 * Step-up re-authentication (API docs: architecture/step-up-reauth.md).
 *
 * Sensitive API routes answer `403 {code: "STEP_UP_REQUIRED"}` when the
 * session has not re-authenticated as the organization's re-verification
 * policy asks for that action's tier (details: tier, mode, window,
 * window_seconds). The
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
/** The authenticator code is from a time step already used: wait for the next code. */
export const STEP_UP_CODE_USED_CODE = 'STEP_UP_CODE_USED'

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

/** What the refused request said about the rule that asked (403 details). */
export interface StepUpPrompt {
  tier?: 'critical' | 'sensitive' | 'routine'
  mode?: 'every_time' | 'once_per_window' | 'off'
  window?: string
  window_seconds?: number
}

/** The prompt carried by a STEP_UP_REQUIRED error's details, if any. */
export function stepUpPromptOf(details: Record<string, unknown> | undefined): StepUpPrompt {
  if (!details) return {}
  const out: StepUpPrompt = {}
  if (details.tier === 'critical' || details.tier === 'sensitive' || details.tier === 'routine') {
    out.tier = details.tier
  }
  if (
    details.mode === 'every_time' ||
    details.mode === 'once_per_window' ||
    details.mode === 'off'
  ) {
    out.mode = details.mode
  }
  if (typeof details.window === 'string') out.window = details.window
  if (typeof details.window_seconds === 'number') out.window_seconds = details.window_seconds
  return out
}

/**
 * Opens the dialog and resolves true once the user re-authenticated, false
 * when they cancelled.
 */
export type StepUpHandler = (prompt?: StepUpPrompt) => Promise<boolean>

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
export function requestStepUp(prompt?: StepUpPrompt): Promise<boolean> {
  if (typeof window === 'undefined' || !handler) return Promise.resolve(false)
  if (!inFlight) {
    const h = handler
    inFlight = h(prompt)
      .catch(() => false)
      .finally(() => {
        inFlight = null
      })
  }
  return inFlight
}
