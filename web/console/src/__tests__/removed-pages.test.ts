import { describe, expect, it } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'

/**
 * Health (was Operations + System) and Platform scanning (was Platform
 * scanning + Shared sensors) are one page each. The old URLs are gone, with
 * no redirects, so nothing in the console may still link to them.
 */
const ROOT = path.resolve(__dirname, '..')
const REMOVED = [
  '/operations',
  '/system',
  '/system/platform-scanning',
  '/system/shared-sensors',
] as const

function files(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) return e.name === '__tests__' ? [] : files(p)
    return /\.(ts|tsx)$/.test(e.name) ? [p] : []
  })
}

describe('removed console pages', () => {
  it('have no route', () => {
    for (const rel of [
      'app/(console)/operations/page.tsx',
      'app/(console)/system/page.tsx',
      'app/(console)/system/platform-scanning/page.tsx',
      'app/(console)/system/shared-sensors/page.tsx',
    ]) {
      expect(fs.existsSync(path.join(ROOT, rel)), rel).toBe(false)
    }
    expect(fs.existsSync(path.join(ROOT, 'app/(console)/health/page.tsx'))).toBe(true)
    expect(fs.existsSync(path.join(ROOT, 'app/(console)/scanning/platform/page.tsx'))).toBe(true)
  })

  it('are referenced by no href, url or page value', () => {
    const escape = (v: string) => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const quoted = new RegExp(`['"\`](${REMOVED.map(escape).join('|')})(['"\`?#/])`, 'g')
    const offenders: string[] = []
    // features/*/api/* hold API endpoint keys (GET /admin/operations), not pages.
    for (const f of files(ROOT).filter((f) => !f.includes(`${path.sep}api${path.sep}`))) {
      const src = fs.readFileSync(f, 'utf8')
      for (const m of src.matchAll(quoted)) {
        // '/system/<other page>' is a live page; only the exact removed ones count.
        if (m[1] === '/system' && m[2] === '/') continue
        offenders.push(`${path.relative(ROOT, f)}: ${m[0]}`)
      }
    }
    expect(offenders).toEqual([])
  })
})
