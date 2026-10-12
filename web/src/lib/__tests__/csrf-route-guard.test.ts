/**
 * Guard: every route handler under src/app/api that answers a state-changing
 * method checks CSRF itself (`csrfRejection`, src/lib/server-auth-cookies.ts).
 * src/proxy.ts covers pages (Server Actions) but not /api/*, so a new POST
 * route without the call would accept forged requests.
 */
import fs from 'node:fs'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

const API_ROOT = path.resolve(__dirname, '../../app/api')

function routeFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) return routeFiles(p)
    return e.name === 'route.ts' ? [p] : []
  })
}

const WRITE_EXPORT =
  /export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\b/

describe('CSRF route guard', () => {
  const files = routeFiles(API_ROOT)

  it('finds the route handlers', () => {
    expect(files.length).toBeGreaterThan(3)
  })

  it.each(files.map((f) => [path.relative(API_ROOT, f), f]))(
    '%s checks CSRF if it accepts writes',
    (_, file) => {
      const src = fs.readFileSync(file, 'utf8')
      if (!WRITE_EXPORT.test(src)) return
      expect(src).toMatch(/csrfRejection\(request/)
    }
  )
})
