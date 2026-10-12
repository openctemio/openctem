import { beforeEach, describe, expect, it, vi } from 'vitest'

const redirect = vi.fn((url: string) => {
  throw Object.assign(new Error('NEXT_REDIRECT'), { url })
})
vi.mock('next/navigation', () => ({ redirect: (url: string) => redirect(url) }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({ get: vi.fn(() => undefined), set: vi.fn(), delete: vi.fn() })),
  headers: vi.fn(async () => new Headers()),
}))
vi.mock('@/lib/cookies-server', () => ({
  setServerCookie: vi.fn(),
  removeServerCookie: vi.fn(async () => undefined),
}))

import { localLogoutAction } from './local-auth-actions'
import { logoutAction } from './auth-actions'

async function target(run: () => Promise<unknown>): Promise<string> {
  let thrown: unknown
  try {
    await run()
  } catch (err) {
    thrown = err
  }
  expect(String(thrown)).toContain('NEXT_REDIRECT')
  return redirect.mock.calls.at(-1)![0]
}

// A Server Action's argument is client-controlled; sign-out must not become
// an open redirect.
describe.each([
  ['localLogoutAction', localLogoutAction],
  ['logoutAction', logoutAction],
] as const)('%s redirect target', (_name, action) => {
  beforeEach(() => {
    redirect.mockClear()
  })

  it('follows a same-origin path', async () => {
    expect(await target(() => action('/login?redirect=%2Fadmin'))).toBe('/login?redirect=%2Fadmin')
  })

  it('defaults to /login', async () => {
    expect(await target(() => action())).toBe('/login')
  })

  it.each(['https://evil.example/', '//evil.example', '/\\evil.example', 'javascript:alert(1)'])(
    'refuses %j',
    async (bad) => {
      expect(await target(() => action(bad))).toBe('/login')
    }
  )
})
