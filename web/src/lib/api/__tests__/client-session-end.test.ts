/**
 * When the API client ends the session. A route's 401 alone never does: the
 * client refreshes, and only a dead session (the refresh refused with 401)
 * signs the person out. A tenant-scoped route answering 401 TENANT_REQUIRED to
 * a person with no organization open (the first social sign-in, before any
 * organization exists) sends them to the account space; an organization that
 * requires two-factor authentication sends them to its setup.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  refresh: vi.fn(),
  endSession: vi.fn(),
  clearAuth: vi.fn(),
}))

vi.mock('@/lib/auth-refresh-lock', () => ({ refreshSessionShared: mocks.refresh }))
vi.mock('@/stores/auth-store', () => ({
  endSessionAndSignIn: mocks.endSession,
  useAuthStore: { getState: () => ({ clearAuth: mocks.clearAuth, updateToken: vi.fn() }) },
}))

let client: typeof import('@/lib/api/client')
let tenantRequired: typeof import('@/lib/api/tenant-required')
let assign: ReturnType<typeof vi.fn>

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const TENANT_REQUIRED = { code: 'TENANT_REQUIRED', message: 'organization required' }

beforeEach(async () => {
  vi.resetModules()
  vi.useFakeTimers()
  mocks.refresh.mockReset()
  mocks.endSession.mockReset()
  mocks.clearAuth.mockReset()
  assign = vi.fn()
  vi.stubGlobal('location', { ...window.location, pathname: '/', search: '', assign })
  client = await import('@/lib/api/client')
  tenantRequired = await import('@/lib/api/tenant-required')
  tenantRequired.resetTenantRequiredRouting()
})
afterEach(() => {
  vi.runOnlyPendingTimers()
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('apiClient session end', () => {
  it('a tenant-scoped 401 for a person with no organization goes to the account space, never signs out', async () => {
    // /api/auth/refresh renews the account-only token (no organization).
    mocks.refresh.mockResolvedValue({ ok: true, status: 200, accessToken: 'account-token' })
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(401, TENANT_REQUIRED))
    )
    await expect(client.get('/api/v1/me/modules')).rejects.toMatchObject({
      code: 'TENANT_REQUIRED',
    })
    vi.runOnlyPendingTimers()
    expect(assign).toHaveBeenCalledWith('/welcome')
    expect(mocks.endSession).not.toHaveBeenCalled()
    expect(mocks.clearAuth).not.toHaveBeenCalled()
  })

  it('an organization that requires 2FA opens the setup, never signs out', async () => {
    mocks.refresh.mockResolvedValue({ ok: false, status: 403, code: 'MFA_ENROLLMENT_REQUIRED' })
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(401, { code: 'UNAUTHORIZED', message: 'expired' }))
    )
    await expect(client.get('/api/v1/findings')).rejects.toBeTruthy()
    vi.runOnlyPendingTimers()
    expect(assign).toHaveBeenCalledWith('/two-factor-setup?next=%2F')
    expect(mocks.endSession).not.toHaveBeenCalled()
  })

  it('a refresh that got no answer keeps the session', async () => {
    mocks.refresh.mockResolvedValue({ ok: false, status: 0 })
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(401, { code: 'UNAUTHORIZED', message: 'expired' }))
    )
    await expect(client.get('/api/v1/findings')).rejects.toBeTruthy()
    vi.runOnlyPendingTimers()
    expect(mocks.endSession).not.toHaveBeenCalled()
  })

  it('a dead session (the refresh refused with 401) signs out', async () => {
    mocks.refresh.mockResolvedValue({ ok: false, status: 401, code: 'SESSION_EXPIRED' })
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(401, { code: 'UNAUTHORIZED', message: 'expired' }))
    )
    await expect(client.get('/api/v1/findings')).rejects.toBeTruthy()
    vi.runOnlyPendingTimers()
    expect(mocks.clearAuth).toHaveBeenCalled()
    expect(mocks.endSession).toHaveBeenCalledWith(undefined, { reason: 'session_expired' })
  })
})
