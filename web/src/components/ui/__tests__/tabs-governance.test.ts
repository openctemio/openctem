/**
 * Governance: a count inside a tab is always <TabsCount>. Tabs used to carry
 * five different counts (secondary Badge, destructive Badge, palette-coloured
 * Badge, a hand-made rounded-full span, and "Label (N)"), so the same kind of
 * tab looked different from page to page. This test fails if any of those
 * forms comes back inside a <TabsTrigger>.
 */
import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SRC = join(__dirname, '../../..')

/**
 * Files still being migrated by in-flight work. Remove an entry once its
 * tabs use <TabsCount>; never add one for new code.
 */
const PENDING = new Set(['app/(dashboard)/(discovery)/components/vulnerable/page.tsx'])

function* tsxFiles(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (name === 'node_modules' || name === '__tests__') continue
    if (statSync(p).isDirectory()) yield* tsxFiles(p)
    else if (name.endsWith('.tsx')) yield p
  }
}

const TRIGGER = /<TabsTrigger\b[\s\S]*?<\/TabsTrigger>/g
const FORBIDDEN: Array<[string, RegExp]> = [
  ['Badge', /<Badge\b/],
  ['hand-made pill', /className="[^"]*rounded-full[^"]*"/],
  ['"Label (N)"', /\(\{[^}]*\}\)/],
]

describe('tab counts', () => {
  it('use <TabsCount> inside every TabsTrigger', () => {
    const offenders: string[] = []
    for (const file of tsxFiles(SRC)) {
      const rel = relative(SRC, file)
      if (PENDING.has(rel)) continue
      const src = readFileSync(file, 'utf8')
      for (const block of src.match(TRIGGER) ?? []) {
        for (const [what, re] of FORBIDDEN) {
          if (re.test(block)) offenders.push(`${rel}: ${what}`)
        }
      }
    }
    expect(offenders).toEqual([])
  })
})

/**
 * Governance: one tab row per screen. Tabs switch between different things
 * (objects, sections); a status is a filter and goes in the list toolbar as a
 * <SegmentedLens>. Two stacked tab rows read as two levels of navigation and
 * made the approvals page hard to scan. This fails if a file renders more than
 * one <TabsList>.
 */
describe('tab rows', () => {
  it('a file renders at most one <TabsList>', () => {
    const offenders: string[] = []
    for (const file of tsxFiles(SRC)) {
      const n = (readFileSync(file, 'utf8').match(/<TabsList\b/g) ?? []).length
      if (n > 1) offenders.push(`${relative(SRC, file)}: ${n} tab rows`)
    }
    expect(offenders).toEqual([])
  })
})
