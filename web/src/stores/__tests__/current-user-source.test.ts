/**
 * Who is signed in comes from the profile API (`useDisplayUser`), not the
 * auth store. The store is filled only by a client-side login or token
 * refresh; after a reload it stays empty while the session lives in the
 * httpOnly cookie, so a page that read `user.id` from it treated everyone as
 * "not me" (the Scope page disabled Approve for every approver, the pentest
 * pages could not tell the creator or assignee).
 *
 * Allowed readers: the store itself, the shared hooks that fall back to it,
 * and the permission/auth hooks that only read claims next to their own
 * fallbacks.
 */
import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SRC = join(__dirname, '..', '..')
const ALLOWED = new Set([
  'stores/auth-store.ts',
  'hooks/use-display-user.ts',
  'features/auth/hooks/use-permissions.ts',
  'features/auth/hooks/use-auth.ts',
  'lib/permissions/hooks.ts',
])

function files(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (name === '__tests__' || name === 'generated') continue
    if (statSync(full).isDirectory()) files(full, out)
    else if (/\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name)) out.push(full)
  }
  return out
}

const STORE_USER = /\buseUser\(\)|useAuthStore\(\(\s*(\w+)\s*\)\s*=>\s*\1\.user\)/

describe('current user source', () => {
  it('no page or component reads the signed-in user from the auth store', () => {
    const hits = files(SRC)
      .map((f) => relative(SRC, f))
      .filter((f) => !ALLOWED.has(f))
      .filter((f) => STORE_USER.test(readFileSync(join(SRC, f), 'utf8')))
    expect(hits).toEqual([])
  })
})
