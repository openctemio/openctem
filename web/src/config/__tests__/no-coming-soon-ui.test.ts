/**
 * Owner decision D-31: no UI for features that do not exist. A disabled
 * "Coming soon" button, a "(coming soon)" option, a ComingSoonPage or a toast
 * saying "not implemented yet" is a control that pretends; hide it until the
 * backend exists and list it in the build-later issue instead.
 *
 * This walks every non-test source file under src/ and fails on those
 * patterns. Comments that describe the rule are fine; the patterns target
 * rendered UI.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = join(__dirname, '..', '..')

const PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'title="Coming soon"', re: /title=["'{`][^"'`}]*coming soon/i },
  { name: '"(coming soon)" label', re: /\(coming soon\)/i },
  { name: 'ComingSoonPage element', re: /<ComingSoonPage\b/ },
  { name: '"not implemented yet" message', re: /['"`][^'"`]*not implemented yet[^'"`]*['"`]/i },
  { name: 'Coming soon text node', re: />\s*Coming soon\s*</i },
]

/**
 * Known leftovers, each with its owner. Remove the entry when it is fixed;
 * the test fails if an entry no longer matches anything.
 */
const ALLOWED: Record<string, string> = {
  // Defensive branch for a coming_soon nav item. Those items are now filtered
  // out before they reach the nav (isHiddenReleaseStatus), so it never renders.
  'components/layout/nav-group.tsx': 'unreachable: coming_soon items are filtered',
}

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

describe('no "coming soon" UI', () => {
  const files = walk(SRC)
  const hits = new Map<string, string[]>()
  for (const f of files) {
    const src = code(f)
    const found = PATTERNS.filter((p) => p.re.test(src)).map((p) => p.name)
    if (found.length) hits.set(relative(SRC, f), found)
  }

  it('renders no control for a feature that does not exist', () => {
    const offenders = [...hits.entries()]
      .filter(([f]) => !(f in ALLOWED))
      .map(([f, names]) => `${f}: ${names.join(', ')}`)
    expect(
      offenders,
      'Hide the control until the backend exists and add it to the build-later issue.'
    ).toEqual([])
  })

  it('keeps the allowlist honest', () => {
    const stale = Object.keys(ALLOWED).filter((f) => !hits.has(f))
    expect(stale, 'Fixed: remove these from ALLOWED').toEqual([])
  })
})
