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

export type ClientKind = 'metadata_document' | 'organization' | 'dynamic'

export interface ConsentScope {
  scope: string
  title: string
  write: boolean
  /** False when the person holds none of the scope's permissions here. */
  granted: boolean
}

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
  scopes: ConsentScope[]
  expires_at: string
}

export class ConsentError extends Error {
  constructor(
    message: string,
    readonly status: number
  ) {
    super(message)
    this.name = 'ConsentError'
  }
}

const base = (id: string) => `/api/v1/oauth/requests/${encodeURIComponent(id)}`

/** A request id is a UUID; anything else is not sent to the API. */
export function isRequestId(id: string | null | undefined): id is string {
  return !!id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)
}

async function failure(response: Response, fallback: string): Promise<ConsentError> {
  const data = (await response.json().catch(() => ({}))) as { message?: string }
  return new ConsentError(data.message || fallback, response.status)
}

export async function fetchConsentRequest(id: string): Promise<ConsentRequest> {
  const response = await csrfFetch(base(id), { method: 'GET' })
  if (!response.ok) throw await failure(response, 'This request is no longer available')
  return (await response.json()) as ConsentRequest
}

async function decide(id: string, decision: 'approve' | 'deny'): Promise<string> {
  const response = await csrfFetch(`${base(id)}/${decision}`, { method: 'POST' })
  if (!response.ok) throw await failure(response, 'This request is no longer available')
  const data = (await response.json()) as { redirect_to?: string }
  const to = data.redirect_to ?? ''
  if (!isSafeRedirect(to))
    throw new ConsentError('The application gave an address that cannot be opened', 400)
  return to
}

export const approveConsent = (id: string) => decide(id, 'approve')
export const denyConsent = (id: string) => decide(id, 'deny')

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

/** How a client identifies itself, in words. */
export function clientKindLabel(r: Pick<ConsentRequest, 'client_kind' | 'client_host'>): string {
  switch (r.client_kind) {
    case 'metadata_document':
      return r.client_host ? `Published by ${r.client_host}` : 'Published by its provider'
    case 'organization':
      return 'Registered by your organization'
    default:
      return 'Unverified: registered itself'
  }
}
