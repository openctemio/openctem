import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { NextRequest } from 'next/server'

class Redirect extends Error {
  constructor(public to: string) {
    super(`redirect:${to}`)
  }
}

vi.mock('next/navigation', () => ({
  redirect: vi.fn((to: string) => {
    throw new Redirect(to)
  }),
}))
const completeSSOLinkCallback = vi.fn()
vi.mock('@/features/sso/actions/sso-link-actions', () => ({
  completeSSOLinkCallback: (...args: unknown[]) => completeSSOLinkCallback(...args),
}))

import { GET } from '../route'

async function call(provider: string, query: string): Promise<string> {
  const url = new URL(`https://app.example.com/auth/sso/link/${provider}?${query}`)
  try {
    await GET({ nextUrl: url } as unknown as NextRequest, { params: Promise.resolve({ provider }) })
  } catch (e) {
    if (e instanceof Redirect) return e.to
    throw e
  }
  throw new Error('the handler returned without a redirect')
}

describe('SSO link route handler', () => {
  beforeEach(() => {
    completeSSOLinkCallback.mockReset()
    completeSSOLinkCallback.mockResolvedValue({ success: true })
  })

  it('finishes the link and says so on Account > Security', async () => {
    expect(await call('entra_id', 'code=c&state=s')).toBe('/account/security?sso_linked=1')
    expect(completeSSOLinkCallback).toHaveBeenCalledWith('entra_id', 'c', 's')
  })

  it('carries the API code of a refusal, never free text', async () => {
    completeSSOLinkCallback.mockResolvedValue({ success: false, code: 'IDENTITY_LINKED_ELSEWHERE' })
    expect(await call('okta', 'code=c&state=s')).toBe(
      '/account/security?sso_link_error=IDENTITY_LINKED_ELSEWHERE'
    )
  })

  it('refuses an unknown provider, a provider error and a missing code without calling the API', async () => {
    expect(await call('facebook', 'code=c&state=s')).toBe(
      '/account/security?sso_link_error=INVALID_PROVIDER'
    )
    const to = await call('okta', 'error=access_denied&error_description=%3Cscript%3E')
    expect(to).toBe('/account/security?sso_link_error=SSO_PROVIDER_ERROR')
    expect(await call('okta', 'state=s')).toBe('/account/security?sso_link_error=SSO_INVALID_STATE')
    expect(completeSSOLinkCallback).not.toHaveBeenCalled()
  })
})
