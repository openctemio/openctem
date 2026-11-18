/**
 * "Is this mine" decisions (your own request, the "Mine" filter, an owner's
 * rights, a per-person draft key) take the signed-in person's id from the
 * profile through `useMyUserId`. The auth store's user is empty on most page
 * loads (the session token is an httpOnly cookie), so an id read from it made
 * your own rows look like someone else's: no "You", no Remind or Withdraw.
 *
 * Part 1 checks the hook: the profile's id, never the store's.
 * Part 2 walks every non-test source file under src/ and fails on a user id
 * read from the auth store outside the store itself and the display hook (which
 * reads the profile first).
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { renderHook } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const profile = vi.hoisted(() => ({ value: undefined as { id: string } | undefined }))
vi.mock('@/features/account/api/use-profile', () => ({
  useProfile: () => ({ profile: profile.value }),
}))
vi.mock('@/stores/auth-store', () => ({
  useAuthStore: (sel: (s: { user: { id: string } }) => unknown) =>
    sel({ user: { id: 'auth-store-id' } }),
}))

import { useMyUserId } from '../use-my-user-id'

describe('useMyUserId', () => {
  beforeEach(() => {
    profile.value = undefined
  })

  it('is the profile id', () => {
    profile.value = { id: 'profile-id' }
    expect(renderHook(() => useMyUserId()).result.current).toBe('profile-id')
  })

  it('is undefined until the profile loads, even when the auth store has a user', () => {
    expect(renderHook(() => useMyUserId()).result.current).toBeUndefined()
  })
})

const SRC = join(__dirname, '..', '..')

const PATTERNS: { name: string; re: RegExp }[] = [
  {
    name: 'user id from the auth store',
    re: /useAuthStore\(\s*\(?\s*(\w+)\s*\)?\s*=>\s*\1\.user\??\.id\b/,
  },
  { name: 'user id from the auth store state', re: /useAuthStore\.getState\(\)\.user\??\.id\b/ },
]

/** Files that own a source of the user id (not "is this mine" decisions). */
const OWNERS = new Set([
  'stores/auth-store.ts',
  'hooks/use-display-user.ts',
  'hooks/use-my-user-id.ts',
])

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      if (entry === '__tests__' || entry === 'node_modules' || entry === 'generated') continue
      walk(full, out)
    } else if (/\.(tsx?|jsx?)$/.test(entry) && !/\.(test|spec)\./.test(entry)) {
      out.push(full)
    }
  }
  return out
}

/** Source with comments stripped, so a comment describing the rule passes. */
function code(file: string): string {
  return readFileSync(file, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
}

describe('"is this mine" uses the profile id', () => {
  it('finds the patterns it guards against', () => {
    const [store, state] = PATTERNS.map((p) => p.re)
    expect(store.test('const me = useAuthStore((s) => s.user?.id)')).toBe(true)
    expect(store.test('useAuthStore((state) => state.user.id)')).toBe(true)
    expect(state.test('useAuthStore.getState().user?.id')).toBe(true)
    expect(store.test('useAuthStore((s) => s.user?.permissions)')).toBe(false)
  })

  it('no source file reads the user id from the auth store', () => {
    const hits: string[] = []
    for (const f of walk(SRC)) {
      const rel = relative(SRC, f).split('\\').join('/')
      if (OWNERS.has(rel)) continue
      const src = code(f)
      for (const p of PATTERNS) if (p.re.test(src)) hits.push(`${rel}: ${p.name}`)
    }
    expect(hits, 'use useMyUserId() from @/hooks/use-my-user-id').toEqual([])
  })
})
