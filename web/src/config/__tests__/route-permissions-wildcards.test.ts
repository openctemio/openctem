import { readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

import { routePermissions } from '../route-permissions'

// A '/x/**' guard needs a page below /x; without one it guards nothing.
// These two are kept on purpose: their tests pin the guard of the old paths.
const KEPT = new Set(['/assets/suggestions/**', '/sensors/**'])

function pageRoutes(): string[] {
  const root = join(process.cwd(), 'src/app')
  const out: string[] = []
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name)
      if (statSync(p).isDirectory()) walk(p)
      else if (name === 'page.tsx') {
        out.push(
          '/' +
            relative(root, dir)
              .split('/')
              .filter((s) => !/^\(.*\)$/.test(s))
              .join('/')
        )
      }
    }
  }
  walk(root)
  return out
}

describe('route permission wildcards', () => {
  it('every /** entry has a page below it', () => {
    const pages = pageRoutes()
    const dead = Object.keys(routePermissions)
      .filter((k) => k.endsWith('/**') && !KEPT.has(k))
      .filter((k) => !pages.some((p) => p.startsWith(k.slice(0, -2))))
    expect(dead).toEqual([])
  })
})
