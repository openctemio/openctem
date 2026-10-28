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
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (cookieJar.has(name) ? { name, value: cookieJar.get(name) } : undefined),
    set: vi.fn(),
    delete: vi.fn(),
  })),
}))
vi.mock('next/navigation', () => ({
  redirect: vi.fn((to: string) => {
    throw new Redirect(to)
  }),
}))
const handleOAuthCallback = vi.fn()
vi.mock('@/features/auth/actions/social-auth-actions', () => ({
  handleOAuthCallback: (...args: unknown[]) => handleOAuthCallback(...args),
}))

import { GET } from '../route'

async function callback(provider: string, query: string): Promise<string> {
  const url = new URL(`https://app.example.com/auth/callback/${provider}?${query}`)
  const request = { nextUrl: url } as unknown as NextRequest
  try {
    await GET(request, { params: Promise.resolve({ provider }) })
  } catch (e) {
    if (e instanceof Redirect) return e.to
    throw e
  }
  throw new Error('the handler returned without a redirect')
}

describe('OAuth callback route handler', () => {
  beforeEach(() => {
    cookieJar.clear()
    handleOAuthCallback.mockReset()
    handleOAuthCallback.mockResolvedValue({ success: true })
  })

  it('refuses an unknown provider before calling the backend', async () => {
    expect(await callback('facebook', 'code=c&state=s')).toBe('/login?error=invalid_provider')
    expect(handleOAuthCallback).not.toHaveBeenCalled()
  })

  it('never echoes the provider error text on the login page', async () => {
    const to = await callback('google', 'error=access_denied&error_description=%3Cscript%3E')
    expect(to).toBe('/login?error=provider_error')
    expect(to).not.toContain('script')
    expect(handleOAuthCallback).not.toHaveBeenCalled()
  })

  it('needs both code and state', async () => {
    expect(await callback('github', 'code=c')).toBe('/login?error=missing_params')
    expect(handleOAuthCallback).not.toHaveBeenCalled()
  })

  it('lands on the same-site path kept in the oauth_redirect cookie', async () => {
    cookieJar.set('oauth_redirect', '/findings?severity=high')
    expect(await callback('microsoft', 'code=c&state=s')).toBe('/findings?severity=high')
    expect(handleOAuthCallback).toHaveBeenCalledWith('microsoft', 'c', 's')
  })

  it.each(['//evil.example', 'https://evil.example/', 'javascript:alert(1)', '/\\evil.example'])(
    'ignores an off-site oauth_redirect cookie: %j',
    async (bad) => {
      cookieJar.set('oauth_redirect', bad)
      expect(await callback('google', 'code=c&state=s')).toBe('/')
    }
  )

  it('sends a failed exchange to the login error, not to the saved path', async () => {
    cookieJar.set('oauth_redirect', '/findings')
    handleOAuthCallback.mockResolvedValue({ success: false, code: 'whatever' })
    expect(await callback('google', 'code=c&state=s')).toBe('/login?error=callback_failed')
  })
})
