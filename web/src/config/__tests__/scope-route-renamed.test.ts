/**
 * The Scoping page moved from /scope-config to /scope with no redirect (owner
 * decision 2026-10-07: few users, a clean rename). No link, nav entry,
 * redirect, test or e2e spec may still point at the old URL, or it would
 * 404.
 */
import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const WEB = join(__dirname, '..', '..', '..')
const ROOTS = ['src', 'e2e'].map((d) => join(WEB, d))
const SELF = relative(WEB, __filename)
const OLD = '/scope' + '-config'

function files(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'generated') continue
    const full = join(dir, name)
    if (statSync(full).isDirectory()) files(full, out)
    else if (/\.(tsx?|json|mjs)$/.test(name)) out.push(full)
  }
  return out
}

describe('the /scope rename', () => {
  it('leaves no reference to the old URL', () => {
    const hits = ROOTS.flatMap((r) => files(r))
      .filter((f) => relative(WEB, f) !== SELF)
      .filter((f) => readFileSync(f, 'utf8').includes(OLD))
      .map((f) => relative(WEB, f))
    expect(hits).toEqual([])
  })
  it('has no inline status switch on the Scope page (research/53 SC5)', () => {
    const page = readFileSync(join(WEB, 'src/app/(dashboard)/(scoping)/scope/page.tsx'), 'utf8')
    expect(page).not.toContain('@/components/ui/switch')
    expect(page).not.toMatch(/<Switch\b/)
  })
})
