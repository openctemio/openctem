/**
 * The scan dialogs and the run drawer load on first open
 * (features/scans/components/lazy-dialogs.tsx). A static import of one of
 * them from a page or a shared component puts the scan wizard (workflow
 * graph, form schemas, cron parsing) back into that page's first-load JS:
 * measured 310 to 390 KB gzipped on each Scans page.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = join(process.cwd(), 'src')
const SCANS = 'features/scans/components'

// The modules that must load on demand.
const HEAVY = [
  'new-scan/new-scan-dialog',
  'quick-scan-dialog',
  'edit-scan-dialog',
  'clone-scan-dialog',
  'scan-assets-dialog',
  'run-detail-sheet',
]
const HEAVY_NAMES = [
  'NewScanDialog',
  'QuickScanDialog',
  'EditScanDialog',
  'CloneScanDialog',
  'ScanAssetsDialog',
  'RunDetailSheet',
]

// Files allowed to import them: the lazy wrappers, the barrels and the
// dialogs that build on each other.
const ALLOWED = new Set(
  [
    'lazy-dialogs.tsx',
    'index.ts',
    'new-scan/index.ts',
    'edit-scan-dialog.tsx',
    'clone-scan-dialog.tsx',
  ].map((f) => `${SCANS}/${f}`)
)

function files(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) {
      if (name !== '__tests__' && name !== 'node_modules') files(path, out)
    } else if (/\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name)) out.push(path)
  }
  return out
}

/** Value imports of a heavy module, by path or by name through the barrel. */
function heavyImports(text: string): string[] {
  const found: string[] = []
  for (const m of text.matchAll(/^import\s+(?!type\s)([^;]*?)\s+from\s+['"]([^'"]+)['"]/gm)) {
    const [, what, spec] = m
    if (HEAVY.some((h) => spec.endsWith(`/${h}`) || spec === `./${h}`)) found.push(spec)
    else if (/features\/scans\/components$|^\.\/new-scan$/.test(spec)) {
      // `{ A, type B }`: only value names count.
      const names = what
        .replace(/[{}]/g, '')
        .split(',')
        .map((n) => n.trim())
        .filter((n) => n && !n.startsWith('type '))
      for (const n of names) if (HEAVY_NAMES.includes(n)) found.push(`${spec} ${n}`)
    }
  }
  return found
}

describe('scan dialogs load on first open', () => {
  it('no page or shared component imports a scan dialog statically', () => {
    const offending = files(SRC)
      .map((f) => relative(SRC, f))
      .filter((f) => !ALLOWED.has(f))
      .flatMap((f) => heavyImports(readFileSync(join(SRC, f), 'utf8')).map((i) => `${f}: ${i}`))
    expect(
      offending,
      'import the Lazy* wrapper from features/scans/components/lazy-dialogs'
    ).toEqual([])
  })

  it('the scanner sees direct, barrel and type-only imports correctly', () => {
    expect(heavyImports("import { RunDetailSheet } from './run-detail-sheet'")).toHaveLength(1)
    expect(
      heavyImports("import { CloneScanDialog, EditScanDialog } from '@/features/scans/components'")
    ).toHaveLength(2)
    expect(
      heavyImports(
        "import type { ScanCandidate } from '@/features/scans/components/scan-assets-dialog'"
      )
    ).toEqual([])
    expect(
      heavyImports("import { type ScanCandidate } from '@/features/scans/components'")
    ).toEqual([])
  })
})
