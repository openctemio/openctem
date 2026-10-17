import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  adminFetch,
  AdminApiError,
  ADMIN_STEP_UP_HEADER,
  setAdminCsrfToken,
  setAdminStepUpPrompt,
} from '../api/admin-client'
// Static import: the component tree is heavy to transform, and a dynamic
// import inside the test counted that cold transform against the 5s timeout.
import { humanizeAction } from '../components/admin-activity-table'

describe('adminFetch', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    // The console session's token, kept in memory (from sign-in/validate).
    setAdminCsrfToken('csrf-123')
    // The page token: echoed only before a console session exists.
    document.cookie = 'csrf_token=page-csrf; path=/'
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  const ok = (body: unknown, status = 200) =>
    new Response(body === undefined ? null : JSON.stringify(body), { status })

  it('reads go to the admin proxy without a CSRF header', async () => {
    fetchMock.mockResolvedValueOnce(ok({ id: '1' }))
    await adminFetch('/tenants')
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/v1/admin/tenants')
    expect(init.headers['X-CSRF-Token']).toBeUndefined()
    expect(init.credentials).toBe('same-origin')
  })

  it('before a session, the sign-in steps echo the page token, never a console cookie', async () => {
    setAdminCsrfToken(null)
    document.cookie = 'admin_csrf=api-only; path=/'
    document.cookie = 'admin_csrf_ui=old-copy; path=/'
    fetchMock.mockResolvedValueOnce(ok({ status: 'mfa_required' }))
    await adminFetch('/auth/login', { method: 'POST', body: { email: 'a@b.c', password: 'x' } })
    expect(fetchMock.mock.calls[0][1].headers['X-CSRF-Token']).toBe('page-csrf')
    document.cookie = 'admin_csrf=; path=/; max-age=0'
    document.cookie = 'admin_csrf_ui=; path=/; max-age=0'
  })

  it('keeps the token from the TOTP step, validate and the IdP callback, in memory only', async () => {
    setAdminCsrfToken(null)
    const cookiesBefore = document.cookie
    fetchMock.mockResolvedValueOnce(ok({ id: '1', csrf_token: 'from-mfa' }))
    await adminFetch('/auth/mfa', { method: 'POST', body: { code: '123456' } })
    fetchMock.mockResolvedValueOnce(ok({}))
    await adminFetch('/tenants', { method: 'POST', body: {} })
    expect(fetchMock.mock.calls[1][1].headers['X-CSRF-Token']).toBe('from-mfa')

    fetchMock.mockResolvedValueOnce(ok({ id: '1', csrf_token: 'from-validate' }))
    await adminFetch('/auth/validate')
    fetchMock.mockResolvedValueOnce(ok({ status: 'signed_in', admin: { csrf_token: 'from-idp' } }))
    await adminFetch('/auth/idp/callback', { method: 'POST', body: {} })
    fetchMock.mockResolvedValueOnce(ok({}))
    await adminFetch('/tenants', { method: 'POST', body: {} })
    expect(fetchMock.mock.calls[4][1].headers['X-CSRF-Token']).toBe('from-idp')
    // Never written to a cookie a tenant page on the same host could read.
    expect(document.cookie).toBe(cookiesBefore)
  })

  it('forgets the token when the session ends', async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }))
    await adminFetch('/auth/logout', { method: 'POST' })
    fetchMock.mockResolvedValueOnce(ok({}))
    await adminFetch('/auth/login', { method: 'POST', body: {} })
    expect(fetchMock.mock.calls[1][1].headers['X-CSRF-Token']).toBe('page-csrf')

    setAdminCsrfToken('csrf-123')
    fetchMock.mockResolvedValueOnce(ok({ code: 'UNAUTHORIZED' }, 401))
    await expect(adminFetch('/auth/validate')).rejects.toBeInstanceOf(AdminApiError)
    fetchMock.mockResolvedValueOnce(ok({}))
    await adminFetch('/auth/login', { method: 'POST', body: {} })
    expect(fetchMock.mock.calls[3][1].headers['X-CSRF-Token']).toBe('page-csrf')
  })

  it('writes carry the console session token, not the page one', async () => {
    fetchMock.mockResolvedValueOnce(ok({ enforced: true }))
    await adminFetch('/tenants/t1/sso/enforcement', { method: 'PUT', body: { enforced: true } })
    const [, init] = fetchMock.mock.calls[0]
    expect(init.headers['X-CSRF-Token']).toBe('csrf-123')
    expect(init.body).toBe(JSON.stringify({ enforced: true }))
  })

  it('returns undefined for 204', async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }))
    await expect(adminFetch('/auth/logout', { method: 'POST' })).resolves.toBeUndefined()
  })

  it('throws AdminApiError with the API message and status', async () => {
    fetchMock.mockResolvedValueOnce(ok({ code: 'VALIDATION', message: 'cannot enforce SSO' }, 400))
    const err = (await adminFetch('/x', { method: 'PUT', body: {} }).catch(
      (e: unknown) => e
    )) as AdminApiError
    expect(err).toBeInstanceOf(AdminApiError)
    expect(err.status).toBe(400)
    expect(err.message).toBe('cannot enforce SSO')
  })
})

describe('adminFetch step-up', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    document.cookie = 'admin_csrf=csrf-123; path=/'
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
    setAdminStepUpPrompt(null)
  })
  const stepUp = (message = 'Confirm this action') =>
    new Response(JSON.stringify({ code: 'ADMIN_STEP_UP_REQUIRED', message }), { status: 401 })

  it('asks for a code and retries the same write with the step-up header', async () => {
    const prompt = vi.fn().mockResolvedValue('123456')
    setAdminStepUpPrompt(prompt)
    fetchMock
      .mockResolvedValueOnce(stepUp())
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 'a1' }), { status: 201 }))
    await expect(
      adminFetch('/administrators', { method: 'POST', body: { email: 'x@example.com' } })
    ).resolves.toEqual({ id: 'a1' })
    expect(prompt).toHaveBeenCalledWith(undefined)
    expect(fetchMock.mock.calls[0][1].headers[ADMIN_STEP_UP_HEADER]).toBeUndefined()
    const retry = fetchMock.mock.calls[1][1]
    expect(retry.headers[ADMIN_STEP_UP_HEADER]).toBe('123456')
    expect(retry.headers['X-CSRF-Token']).toBe('csrf-123')
    expect(retry.body).toBe(JSON.stringify({ email: 'x@example.com' }))
  })

  it('shows the refusal of a wrong code on the next prompt', async () => {
    const prompt = vi.fn().mockResolvedValueOnce('000000').mockResolvedValueOnce('654321')
    setAdminStepUpPrompt(prompt)
    fetchMock
      .mockResolvedValueOnce(stepUp())
      .mockResolvedValueOnce(stepUp('Invalid or already used code'))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    await adminFetch('/users/u1', { method: 'DELETE' })
    expect(prompt).toHaveBeenNthCalledWith(2, 'Invalid or already used code')
    expect(fetchMock.mock.calls[2][1].headers[ADMIN_STEP_UP_HEADER]).toBe('654321')
  })

  it('gives up when the administrator cancels', async () => {
    setAdminStepUpPrompt(vi.fn().mockResolvedValue(null))
    fetchMock.mockResolvedValueOnce(stepUp())
    const err = (await adminFetch('/platform-idp', { method: 'DELETE' }).catch(
      (e: unknown) => e
    )) as AdminApiError
    expect(err.code).toBe('ADMIN_STEP_UP_REQUIRED')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('sends a code the caller already has without prompting', async () => {
    const prompt = vi.fn()
    setAdminStepUpPrompt(prompt)
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 201 }))
    await adminFetch('/tenants/t1/users', { method: 'POST', body: {}, stepUpCode: '111222' })
    expect(fetchMock.mock.calls[0][1].headers[ADMIN_STEP_UP_HEADER]).toBe('111222')
    expect(prompt).not.toHaveBeenCalled()
  })

  it('sends a code the form put in the body as the step-up header too', async () => {
    const prompt = vi.fn()
    setAdminStepUpPrompt(prompt)
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }))
    await adminFetch('/settings/legal', {
      method: 'PUT',
      body: { totp_code: '445566', version: 2 },
    })
    expect(fetchMock.mock.calls[0][1].headers[ADMIN_STEP_UP_HEADER]).toBe('445566')
    const form = new FormData()
    form.set('totp_code', '778899')
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 201 }))
    await adminFetch('/content-packs', { method: 'POST', body: form })
    expect(fetchMock.mock.calls[1][1].headers[ADMIN_STEP_UP_HEADER]).toBe('778899')
    expect(prompt).not.toHaveBeenCalled()
  })

  it('never prompts for other refusals', async () => {
    const prompt = vi.fn()
    setAdminStepUpPrompt(prompt)
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: 'STEP_UP_REQUIRED', message: 'x' }), { status: 401 })
    )
    await expect(adminFetch('/settings/legal', { method: 'PUT', body: {} })).rejects.toBeInstanceOf(
      AdminApiError
    )
    expect(prompt).not.toHaveBeenCalled()
  })
})

describe('humanizeAction', () => {
  it('reads audit actions as words, with acronyms kept', () => {
    expect(humanizeAction('organization.idp_create')).toBe('Identity provider create')
    expect(humanizeAction('console.mfa_enrolled')).toBe('Two-step verification enrolled')
    expect(humanizeAction('organization.sso_enforcement')).toBe('SSO enforcement')
  })
})
