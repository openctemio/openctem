/**
 * ScannerText renders markdown with react-markdown (parser and syntax tree,
 * about 40 KB gzipped). The shared components barrel (./index.ts) is imported
 * by nearly every page, so a re-export there put that parser into the
 * first-load JS of every route (median 472 to 514 KB, scripts/route-js-budget).
 * ScannerText is imported from its own module, only by the pages that render
 * scanner text.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const DIR = join(process.cwd(), 'src/features/shared/components')

describe('shared components barrel', () => {
  it('does not re-export scanner-text', () => {
    const barrel = readFileSync(join(DIR, 'index.ts'), 'utf8')
    expect(barrel).not.toMatch(/from\s+['"]\.\/scanner-text['"]/)
  })

  it('re-exports no module that imports react-markdown', () => {
    const barrel = readFileSync(join(DIR, 'index.ts'), 'utf8')
    const modules = [...barrel.matchAll(/from\s+['"]\.\/([^'"]+)['"]/g)].map((m) => m[1])
    const heavy = modules.filter((m) => {
      for (const ext of ['.tsx', '.ts']) {
        try {
          return /from\s+['"]react-markdown['"]/.test(readFileSync(join(DIR, m + ext), 'utf8'))
        } catch {
          // try the next extension
        }
      }
      return false
    })
    expect(heavy).toEqual([])
  })
})
