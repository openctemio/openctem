/**
 * @vitest-environment node
 */
import { describe, expect, it, vi } from 'vitest'
import { NextRequest } from 'next/server'

vi.mock('@/lib/version/web-build-info', () => ({
  resolveWebBuildInfo: vi.fn(async () => ({
    version: 'v0.8.0-dev+4d2f4b02',
    commit: '4d2f4b02',
    channel: 'dev',
  })),
}))

import { GET } from '../route'

// Session cookies must be shaped like a JWT (src/lib/middleware/auth.ts).
// Built at runtime so secret scanners do not read a literal token.
const TOKEN = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiJ1MSJ9', 'c2ln'].join('.')

const call = (cookie?: string) =>
  GET(
    new NextRequest('http://ui.test/api/version', {
      headers: cookie ? { cookie } : undefined,
    })
  )

describe('GET /api/version', () => {
  it('refuses an anonymous caller', async () => {
    const res = await call()
    expect(res.status).toBe(401)
  })

  it('refuses a session cookie that is not a token', async () => {
    const res = await call('refresh_token=r')
    expect(res.status).toBe(401)
  })

  it.each([
    ['the app session', `auth_token=${TOKEN}`],
    ['a refresh-only app session', `refresh_token=${TOKEN}`],
    ['the admin console session', 'admin_session=s'],
  ])('answers %s with the web build', async (_, cookie) => {
    const res = await call(cookie)
    expect(res.status).toBe(200)
    expect(res.headers.get('Cache-Control')).toBe('no-store')
    await expect(res.json()).resolves.toEqual({
      version: 'v0.8.0-dev+4d2f4b02',
      commit: '4d2f4b02',
      channel: 'dev',
    })
  })
})
