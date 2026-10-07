/**
 * Every endpoint builder names a route the API registers (RFC-041 §7).
 *
 * The web once called paths the server never had (POST /auth/resend-verification,
 * POST /integrations/{id}/send, ...): each would have answered 404, and nothing
 * noticed because no check compared the two. This calls every builder in the
 * endpoint modules with placeholder arguments and matches the path it returns
 * against api/api/openapi/routes.txt, the generated list of every registered
 * operation. The file is not committed: `make generate` at the repository
 * root writes it from the router (Web CI does the same).
 *
 * Builders that point at no route today are frozen in
 * endpoint-route-baseline.txt. The baseline only shrinks: a new builder without
 * a route fails, and so does a baseline line that now has one.
 */
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

import * as endpoints from '../endpoints'
import * as securityEndpoints from '../security-endpoints'

const here = resolve(__dirname)
const manifestPath = resolve(here, '../../../../../api/api/openapi/routes.txt')
const baselinePath = resolve(here, 'endpoint-route-baseline.txt')

if (!existsSync(manifestPath)) {
  throw new Error(
    'api/api/openapi/routes.txt is missing. It is generated from the router, not ' +
      'committed: run `make generate` at the repository root.'
  )
}

function lines(path: string): string[] {
  return readFileSync(path, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'))
}

// Route patterns with every parameter written {}; a placeholder segment in a
// built path matches any parameter.
const routePaths = lines(manifestPath).map((l) => l.split(' ')[1])
const routeMatchers = routePaths.map(
  (p) => new RegExp('^' + p.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\{\}/g, '[^/]+') + '$')
)

const PLACEHOLDER = 'p0'

function builtPath(fn: (...args: unknown[]) => unknown): string | null {
  const args = Array.from({ length: fn.length }, () => PLACEHOLDER)
  let out: unknown
  try {
    out = fn(...args)
  } catch {
    try {
      out = fn()
    } catch {
      return null
    }
  }
  if (typeof out !== 'string' || !out.startsWith('/')) return null
  return out.split('?')[0].replace(/\/+$/, '') || '/'
}

interface Target {
  name: string
  path: string
}

function collect(mod: Record<string, unknown>, prefix: string): Target[] {
  const out: Target[] = []
  for (const [groupName, group] of Object.entries(mod)) {
    if (!group || typeof group !== 'object') continue
    for (const [key, value] of Object.entries(group as Record<string, unknown>)) {
      if (typeof value !== 'function') continue
      const path = builtPath(value as (...args: unknown[]) => unknown)
      if (path && path.startsWith('/api/')) {
        out.push({ name: `${prefix}.${groupName}.${key}`, path })
      }
    }
  }
  return out
}

const targets = [
  ...collect(endpoints as Record<string, unknown>, 'endpoints'),
  ...collect(securityEndpoints as Record<string, unknown>, 'security-endpoints'),
]

describe('endpoint builders target registered routes', () => {
  it('reads the route manifest and the builders', () => {
    expect(routePaths.length).toBeGreaterThan(500)
    expect(targets.length).toBeGreaterThan(300)
  })

  it('every builder names a registered route, or is baselined', () => {
    const baseline = new Set(lines(baselinePath))
    const missing = targets.filter((t) => !routeMatchers.some((m) => m.test(t.path)))
    const missingNames = new Set(missing.map((t) => t.name))

    const fresh = missing.filter((t) => !baseline.has(t.name)).map((t) => `${t.name}  -> ${t.path}`)
    const stale = [...baseline].filter((name) => !missingNames.has(name))

    expect(
      fresh,
      'endpoint builders that name no API route (fix the path or remove the builder)'
    ).toEqual([])
    expect(stale, 'baseline lines that now match a route or no longer exist (delete them)').toEqual(
      []
    )
  })
})
