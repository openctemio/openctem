import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { NextRequest } from 'next/server'

// redirect() never returns in Next.js: it throws. The mock does the same so a
// test sees the first redirect the handler takes, and nothing after it runs.
class Redirect extends Error {
  constructor(public to: string) {
    super(`redirect:${to}`)
  }
}

const cookieJar = new Map<string, string>()
const deleted: string[] = []
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (cookieJar.has(name) ? { name, value: cookieJar.get(name) } : undefined),
    set: vi.fn(),
    delete: (name: string) => deleted.push(name),
  })),
}))
vi.mock('next/navigation', () => ({
  redirect: vi.fn((to: string) => {
    throw new Redirect(to)
  }),
}))
const handleSSOCallback = vi.fn()
vi.mock('@/features/sso/actions/sso-auth-actions', () => ({
  handleSSOCallback: (...args: unknown[]) => handleSSOCallback(...args),
}))

import { GET } from '../route'

async function callback(provider: string, query: string): Promise<string> {
  const url = new URL(`https://app.example.com/auth/sso/callback/${provider}?${query}`)
  const request = { nextUrl: url } as unknown as NextRequest
  try {
    await GET(request, { params: Promise.resolve({ provider }) })
  } catch (e) {
    if (e instanceof Redirect) return e.to
    throw e
  }
  throw new Error('the handler returned without a redirect')
}

describe('organization SSO callback route handler', () => {
  beforeEach(() => {
    cookieJar.clear()
    deleted.length = 0
    handleSSOCallback.mockReset()
    handleSSOCallback.mockResolvedValue({ success: true })
  })

  it('is a route handler, so the callback may write the session cookies', async () => {
    const mod = await import('../route')
    expect(typeof mod.GET).toBe('function')
    expect(mod.dynamic).toBe('force-dynamic')
  })

  it('refuses an unknown provider before calling the backend', async () => {
    cookieJar.set('sso_org', 'acme')
    expect(await callback('github', 'code=c&state=s')).toBe(
      '/login?error=invalid_provider&org=acme'
    )
    expect(handleSSOCallback).not.toHaveBeenCalled()
  })

  it('never echoes the provider error text on the login page', async () => {
    const to = await callback('entra_id', 'error=access_denied&error_description=%3Cscript%3E')
    expect(to).toBe('/login?error=provider_error')
    expect(to).not.toContain('script')
    expect(handleSSOCallback).not.toHaveBeenCalled()
  })

  it('needs both code and state', async () => {
    expect(await callback('okta', 'code=c')).toBe('/login?error=missing_params')
    expect(handleSSOCallback).not.toHaveBeenCalled()
  })

  it('completes the sign-in and lands on the same-site path kept in the sso_redirect cookie', async () => {
    cookieJar.set('sso_redirect', '/findings?severity=high')
    cookieJar.set('sso_org', 'acme')
    expect(await callback('entra_id', 'code=c&state=s')).toBe('/findings?severity=high')
    expect(handleSSOCallback).toHaveBeenCalledWith('entra_id', 'c', 's')
    expect(deleted).toContain('sso_org')
  })

  it.each(['//evil.example', 'https://evil.example/', 'javascript:alert(1)', '/\\evil.example'])(
    'ignores an off-site sso_redirect cookie: %j',
    async (bad) => {
      cookieJar.set('sso_redirect', bad)
      expect(await callback('entra_id', 'code=c&state=s')).toBe('/')
    }
  )

  it('maps the API refusal code, never its text, and keeps the organization', async () => {
    cookieJar.set('sso_org', 'acme')
    handleSSOCallback.mockResolvedValue({
      success: false,
      code: 'SSO_NOT_A_MEMBER',
      error: '<b>raw</b>',
    })
    const to = await callback('entra_id', 'code=c&state=s')
    expect(to.startsWith('/login?error=')).toBe(true)
    expect(to).toContain('org=acme')
    expect(to).not.toContain('raw')
  })
})
