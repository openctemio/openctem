/**
 * The Remediation console (api/docs/rfcs/RFC-098-remediation-tasks.md): the
 * solution families page (/remediations) is removed and the campaign pages
 * moved to /remediation/campaigns, with no redirects (owner rule: no
 * redirects for renamed pages). No link, nav entry, test or e2e spec may
 * still point at the old URLs, or it would 404.
 */
import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const WEB = join(__dirname, '..', '..', '..')
const ROOTS = ['src', 'e2e'].map((d) => join(WEB, d))
const SELF = relative(WEB, __filename)
// Built so this file does not match itself.
const REMOVED = ['/remediation' + 's', 'remediation-' + 'groups']

function files(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'generated') continue
    const full = join(dir, name)
    if (statSync(full).isDirectory()) files(full, out)
    else if (/\.(tsx?|json|mjs)$/.test(name)) out.push(full)
  }
  return out
}

describe('the removed solution families page', () => {
  it('leaves no reference to its URL or its feature', () => {
    const hits = ROOTS.flatMap((r) => files(r))
      .filter((f) => relative(WEB, f) !== SELF)
      .filter((f) => {
        const text = readFileSync(f, 'utf8')
        // The API route /api/v1/findings/remediation-groups is not the page.
        return REMOVED.some(
          (needle) => text.split(needle).length > 1 && !text.includes(`/api/v1/findings/${needle}`)
        )
      })
      .map((f) => relative(WEB, f))
    expect(hits).toEqual([])
  })

  it('links campaigns at their new URL only', () => {
    const hits = ROOTS.flatMap((r) => files(r))
      .filter((f) => relative(WEB, f) !== SELF)
      .filter((f) => /['"`]\/remediation\/\$\{/.test(readFileSync(f, 'utf8')))
      .map((f) => relative(WEB, f))
    expect(hits).toEqual([])
  })
})
