/**
 * Consent API of the MCP authorization server (RFC-062).
 *
 * An AI application (MCP client) asks to connect to OpenCTEM; the API stores
 * the request and sends the browser to /oauth/consent?request=<id>. The page
 * reads the request in the session's current organization and posts the
 * person's decision. Answering is a browser-session action only: the API
 * refuses API keys here.
 */

import { csrfFetch } from '@/lib/api/client'
import { isStepUpRequired, requestStepUp } from '@/lib/api/step-up'

export type ClientKind = 'metadata_document' | 'organization' | 'dynamic'

export interface ConsentScope {
  scope: string
  title: string
  write: boolean
  /** False when the person holds none of the scope's permissions here. */
  granted: boolean
  /** The organization's policy does not let members grant it. */
  not_allowed: boolean
}

/** Why the organization's policy refuses the application. */
export type ConsentBlocked = 'mcp_disabled' | 'client_not_allowed' | 'device_flow_disabled'

export interface ConsentRequest {
  id: string
  client_name: string
  client_id: string
  client_kind: ClientKind
  /** Host of the client's metadata document (metadata_document clients). */
  client_host?: string
  redirect_host: string
  redirect_uri: string
  loopback_only: boolean
  /** Registered by the organization or published on a host it trusts. */
  verified: boolean
  blocked?: ConsentBlocked
  /** Blocked only because its publisher is not approved: members may ask. */
  requestable?: boolean
  /** The caller may approve the publisher here (settings:write). */
  can_allow?: boolean
  /** A request for this publisher is already waiting. */
  access_requested?: boolean
  scopes: ConsentScope[]
  /**
   * The person's role has full organization data access, so the page offers
   * "Allow access to all organization data" (off by default).
   */
  full_data_available?: boolean
  expires_at: string
  /**
   * "code": the application sent the browser here. "device": a terminal
   * showed a code the person typed in at /oauth/device.
   */
  flow?: 'code' | 'device'
  /** Device flow: where and when the terminal asked, and this browser's address. */
  requester_ip?: string
  requester_user_agent?: string
  requested_at?: string
  your_ip?: string
  same_address?: boolean
}

export class ConsentError extends Error {
  constructor(
    message: string,
    readonly status: number
  ) {
    super(message)
    this.name = 'ConsentError'
  }

  /** The API's error code (STEP_UP_REQUIRED, ...). */
  code?: string
}

const base = (id: string) => `/api/v1/oauth/requests/${encodeURIComponent(id)}`

/** A request id is a UUID; anything else is not sent to the API. */
export function isRequestId(id: string | null | undefined): id is string {
  return !!id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)
}

/**
 * The API's message (English, server generated) or "" so the page shows its
 * own translated text.
 */
async function failure(response: Response): Promise<ConsentError> {
  const data = (await response.json().catch(() => ({}))) as { message?: string; code?: string }
  const err = new ConsentError(data.message || '', response.status)
  err.code = data.code
  return err
}

export async function fetchConsentRequest(id: string): Promise<ConsentRequest> {
  const response = await csrfFetch(base(id), { method: 'GET' })
  if (!response.ok) throw await failure(response)
  return (await response.json()) as ConsentRequest
}

async function decide(
  id: string,
  decision: 'approve' | 'deny',
  fullData = false,
  stepUpRetried = false
): Promise<string> {
  const init: RequestInit = { method: 'POST' }
  if (fullData) {
    init.headers = { 'Content-Type': 'application/json' }
    init.body = JSON.stringify({ full_data: true })
  }
  const response = await csrfFetch(`${base(id)}/${decision}`, init)
  if (!response.ok) {
    const err = await failure(response)
    // Approving needs a recent sign-in: ask for it once, then send the same
    // decision again. Cancelling the dialog keeps the original error.
    if (
      !stepUpRetried &&
      isStepUpRequired({ statusCode: err.status, code: err.code }) &&
      (await requestStepUp())
    ) {
      return decide(id, decision, fullData, true)
    }
    throw err
  }
  const data = (await response.json()) as { redirect_to?: string }
  const to = data.redirect_to ?? ''
  // A terminal sign-in has nowhere to send the browser: "" means done here.
  if (to !== '' && !isSafeRedirect(to)) throw new ConsentError('', 400)
  return to
}

/**
 * fullData allows the connection to read all organization data: offered only
 * to a full-data role (full_data_available) and always needs a fresh step-up.
 */
export const approveConsent = (id: string, fullData = false) => decide(id, 'approve', fullData)
export const denyConsent = (id: string) => decide(id, 'deny')

/**
 * Enters the code a terminal shows (device authorization grant) and returns
 * the id of the request the consent page then shows. Every unusable code is
 * the same 404.
 */
export async function enterDeviceCode(userCode: string): Promise<string> {
  const response = await csrfFetch('/api/v1/oauth/device', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_code: userCode }),
  })
  if (!response.ok) throw await failure(response)
  const data = (await response.json()) as { request_id?: string }
  if (!isRequestId(data.request_id)) throw new ConsentError('', 500)
  return data.request_id
}

/**
 * The browser is only ever sent to an http(s) address. The API has already
 * matched it against the client's registered redirect URIs; this refuses
 * anything else (javascript:, data:) should that ever change.
 */
export function isSafeRedirect(to: string): boolean {
  try {
    const u = new URL(to)
    return u.protocol === 'https:' || u.protocol === 'http:'
  } catch {
    return false
  }
}
