import { beforeEach, describe, expect, it, vi } from 'vitest'

const jar = new Map<string, string>()
const deleted: string[] = []
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (jar.has(name) ? { name, value: jar.get(name) } : undefined),
    set: vi.fn(),
    delete: (name: string) => deleted.push(name),
  })),
}))
vi.mock('@/lib/cookies-server', () => ({ setServerCookie: vi.fn() }))
vi.mock('@/lib/api/browser-context-headers', () => ({
  browserContextHeaders: vi.fn(async () => ({})),
}))

import { bindingCookieName } from '@/features/auth/lib/browser-binding'
import { handleSSOCallback } from '../sso-auth-actions'

const attemptCookies = ['sso_state', 'sso_redirect', bindingCookieName('sso')]

describe('handleSSOCallback single-use cookies', () => {
  beforeEach(() => {
    jar.clear()
    deleted.length = 0
  })

  it('clears the attempt cookies when the state does not match', async () => {
    jar.set('sso_state', 'right')
    jar.set('sso_redirect', '/findings')
    jar.set(bindingCookieName('sso'), 'bind')
    const res = await handleSSOCallback('okta', 'code', 'wrong')
    expect(res.success).toBe(false)
    for (const name of attemptCookies) expect(deleted).toContain(name)
  })

  it('clears the attempt cookies when the browser binding is missing', async () => {
    jar.set('sso_state', 's')
    jar.set('sso_redirect', '/findings')
    const res = await handleSSOCallback('okta', 'code', 's')
    expect(res.success).toBe(false)
    for (const name of attemptCookies) expect(deleted).toContain(name)
  })

  it('clears the attempt cookies when no state cookie exists', async () => {
    jar.set('sso_redirect', '/findings')
    const res = await handleSSOCallback('okta', 'code', 's')
    expect(res.success).toBe(false)
    for (const name of attemptCookies) expect(deleted).toContain(name)
  })
})
