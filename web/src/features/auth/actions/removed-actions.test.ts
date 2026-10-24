import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// A 'use server' export is a public POST endpoint. These actions were
// unreferenced duplicates of the route handlers (one returned a fresh access
// token to its caller, one cleared cookies without ending the API session,
// one posted to a route that does not exist). They stay removed.
const AUTH = join(__dirname, '..')
const REMOVED = [
  'refreshTokenAction',
  'logoutAction',
  'handleOAuthCallback',
  'getCurrentUser',
  'isAuthenticated',
]

describe('removed server actions', () => {
  it('the module and its hook are gone', () => {
    expect(existsSync(join(AUTH, 'actions', 'auth-actions.ts'))).toBe(false)
    expect(existsSync(join(AUTH, 'hooks', 'use-auth.ts'))).toBe(false)
  })

  it('no server action module exports a removed name', () => {
    const dir = join(AUTH, 'actions')
    const modules = readdirSync(dir).filter((f) => /-actions\.ts$/.test(f))
    expect(modules.length).toBeGreaterThan(0)
    for (const file of modules) {
      const src = readFileSync(join(dir, file), 'utf8')
      for (const name of REMOVED) {
        // social-auth-actions has its own, different handleOAuthCallback.
        if (file === 'social-auth-actions.ts' && name === 'handleOAuthCallback') continue
        expect(src, `${file} exports ${name}`).not.toMatch(
          new RegExp(`export\\s+(async\\s+)?(function|const)\\s+${name}\\b`)
        )
      }
    }
  })
})
