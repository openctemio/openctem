/**
 * Governance: a filter is never a Tabs control without panels. Tabs give each
 * trigger aria-controls naming a TabsContent; without the panel the id points
 * at nothing (axe critical aria-valid-attr-value). A list's state filter is the shared
 * FilterSelect token (as on the tenant app's lists); Tabs stay for views with panels.
 */
import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SRC = join(__dirname, '..')

function* tsxFiles(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (name === '__tests__' || name === 'node_modules') continue
    if (statSync(p).isDirectory()) yield* tsxFiles(p)
    else if (name.endsWith('.tsx')) yield p
  }
}

describe('console filters', () => {
  it('no file renders TabsTrigger without TabsContent', () => {
    const offenders: string[] = []
    for (const file of tsxFiles(SRC)) {
      const src = readFileSync(file, 'utf8')
      if (/<TabsTrigger\b/.test(src) && !/<TabsContent\b/.test(src)) {
        offenders.push(relative(SRC, file))
      }
    }
    expect(offenders).toEqual([])
  })

  it.each([
    'app/(console)/users/page.tsx',
    'app/(console)/system/configuration/page.tsx',
    'app/(console)/system/ai-applications/page.tsx',
  ])('%s filters with FilterSelect', (rel) => {
    expect(readFileSync(join(SRC, rel), 'utf8')).toContain('<FilterSelect')
  })
})
