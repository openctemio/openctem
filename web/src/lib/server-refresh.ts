/**
 * Single-flight session refresh for the Next.js server runtime.
 *
 * The API rotates the refresh token on every use and treats a token presented
 * again after its rotation as theft (it ends the session). A page load fires
 * many API calls at once; when the access cookie has expired, each one reaches
 * the server with the same refresh cookie, and requests the browser sent
 * before the first refresh answered keep carrying the old cookie after it.
 * Every route that refreshes (the /api/v1 proxy and /api/auth/refresh) goes
 * through this one function, so:
 *
 * - concurrent calls with the same refresh token share one API call;
 * - for a short while after it settles, late calls with that token get the
 *   same result instead of spending the token again (a success hands out the
 *   same rotated pair; a 401 is not retried with a token known to be dead).
 *
 * Entries are keyed by a SHA-256 of the tenant and the token, never the token
 * itself, and a result only ever goes to a caller presenting that same token
 * (it already holds the session). The map lives on globalThis so every route
 * module of one server process shares it. The API's rotation grace covers the
 * same race across server processes.
 *
 * Design: api/docs/architecture/session-refresh.md
 */

import { createHash } from 'node:crypto'

import { env } from '@/lib/env'
import { rotatedRefreshToken } from '@/lib/server-auth-cookies'

/** A refresh the API accepted. */
export interface ServerRefreshSuccess {
  ok: true
  status: number
  accessToken: string
  /** The rotated refresh token (absent if the API did not send one). */
  refreshToken?: string
  expiresIn: number
  tenantId: string
  tenantSlug: string
  role: string
}

/** A refresh the API refused, or that could not reach it (status 0). */
export interface ServerRefreshFailure {
  ok: false
  status: number
  code?: string
  message?: string
}

export type ServerRefreshResult = ServerRefreshSuccess | ServerRefreshFailure

/** How long a settled result keeps answering late calls with the same token. */
export const SETTLED_REFRESH_TTL_MS = 20_000
/** Bound on remembered results, so a flood of bogus cookies cannot grow memory. */
const MAX_ENTRIES = 5_000

interface Flight {
  promise: Promise<ServerRefreshResult>
  settledAt?: number
}

type FlightStore = Map<string, Flight>

const STORE_KEY = '__openctemServerRefreshFlights'

function store(): FlightStore {
  const g = globalThis as typeof globalThis & { [STORE_KEY]?: FlightStore }
  if (!g[STORE_KEY]) g[STORE_KEY] = new Map()
  return g[STORE_KEY]
}

/** Clears every remembered refresh (tests). */
export function resetServerRefreshFlights(): void {
  store().clear()
}

function flightKey(refreshToken: string, tenantId: string): string {
  return createHash('sha256').update(`${tenantId}\u0000${refreshToken}`).digest('hex')
}

/** Results worth replaying: a success, or a refusal that will not change. */
function isRemembered(result: ServerRefreshResult): boolean {
  return result.ok || result.status === 401
}

function prune(flights: FlightStore, now: number): void {
  for (const [key, flight] of flights) {
    if (flight.settledAt !== undefined && now - flight.settledAt > SETTLED_REFRESH_TTL_MS) {
      flights.delete(key)
    }
  }
  // Still too many: drop the oldest settled entries (Map keeps insertion order).
  if (flights.size > MAX_ENTRIES) {
    for (const [key, flight] of flights) {
      if (flights.size <= MAX_ENTRIES) break
      if (flight.settledAt !== undefined) flights.delete(key)
    }
  }
}

/** Calls the API refresh endpoint once. */
export async function callRefreshEndpoint(
  refreshToken: string,
  tenantId: string
): Promise<ServerRefreshResult> {
  try {
    const response = await fetch(`${env.api.url}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken, tenant_id: tenantId }),
    })
    const data = await response.json().catch(() => ({}))
    if (!response.ok || !data?.access_token) {
      return {
        ok: false,
        status: response.status,
        code: typeof data?.code === 'string' ? data.code : undefined,
        message: typeof data?.message === 'string' ? data.message : undefined,
      }
    }
    return {
      ok: true,
      status: response.status,
      accessToken: data.access_token,
      // The API sends the rotated refresh token in Set-Cookie only.
      refreshToken: rotatedRefreshToken(response, data),
      expiresIn: data.expires_in || 900,
      tenantId: data.tenant_id,
      tenantSlug: data.tenant_slug,
      role: data.role,
    }
  } catch {
    return { ok: false, status: 0, code: 'REFRESH_UNREACHABLE' }
  }
}

/**
 * Refreshes the session for this refresh token and tenant, sharing one API
 * call with every concurrent and recent caller presenting the same token.
 */
export function refreshSessionOnce(
  refreshToken: string,
  tenantId: string,
  call: (
    refreshToken: string,
    tenantId: string
  ) => Promise<ServerRefreshResult> = callRefreshEndpoint
): Promise<ServerRefreshResult> {
  const flights = store()
  const now = Date.now()
  prune(flights, now)

  const key = flightKey(refreshToken, tenantId)
  const existing = flights.get(key)
  if (existing) return existing.promise

  const flight: Flight = {
    promise: call(refreshToken, tenantId).then(
      (result) => {
        if (isRemembered(result)) {
          flight.settledAt = Date.now()
        } else {
          flights.delete(key)
        }
        return result
      },
      (error: unknown) => {
        flights.delete(key)
        throw error
      }
    ),
  }
  flights.set(key, flight)
  return flight.promise
}
