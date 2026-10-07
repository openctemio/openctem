import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

/**
 * List URL convention guard (owner 2026-10-07: "no run_page-style params
 * anywhere"). A list page keeps its paging in `useListParams`: plain `page`,
 * `per_page`, `sort`, `q` and field-named filters. This fails on
 *
 * - a prefixed list parameter (`run_page`, `x_per_page`, `y_sort`), and
 * - a page reading `page` / `per_page` itself through useUrlFilter or
 *   useUrlFilterNumber instead of the shared hook.
 *
 * PENDING lists the pages still to move to useListParams; it only shrinks.
 */
const ROOT = join(__dirname, '..', '..', '..')
const PENDING = new Set<string>([
  'src/app/(dashboard)/settings/audit-log/page.tsx',
  'src/app/(dashboard)/(scoping)/scope/page.tsx',
  'src/app/(dashboard)/(scoping)/attack-surface/external/page.tsx',
  'src/app/(dashboard)/(discovery)/assets/changes/page.tsx',
  'src/app/(dashboard)/(discovery)/assets/suggestions/page.tsx',
  'src/app/(dashboard)/(discovery)/exposures/page.tsx',
  'src/app/(dashboard)/findings/page.tsx',
  'src/app/(admin-console)/admin/(console)/scanning/target-mappings/page.tsx',
  'src/hooks/use-url-pagination.ts',
])

const PREFIXED = /['"`](?!per_page['"`])[a-z][a-z0-9_]*_(page|per_page|sort)['"`]/
const RAW_PAGING = /useUrlFilter(Number)?\(\s*['"`](page|per_page)['"`]/

function walk(path: string, out: string[]) {
  const st = statSync(path)
  if (st.isDirectory()) {
    for (const name of readdirSync(path)) {
      if (name === 'node_modules' || name.startsWith('.') || name === 'generated') continue
      walk(join(path, name), out)
    }
  } else if (/\.tsx?$/.test(path) && !/\.test\.tsx?$/.test(path)) {
    out.push(path)
  }
}

describe('list URL parameters', () => {
  const files: string[] = []
  walk(join(ROOT, 'src'), files)
  const rel = (abs: string) => relative(ROOT, abs).split(sep).join('/')

  it('are never prefixed (run_page, run_per_page, run_sort)', () => {
    const hits = files.flatMap((abs) =>
      readFileSync(abs, 'utf8')
        .split('\n')
        .map((line, i) => (PREFIXED.test(line) ? `${rel(abs)}:${i + 1}: ${line.trim()}` : null))
        .filter((x): x is string => x !== null)
    )
    expect(hits).toEqual([])
  })

  it('page and per_page go through useListParams', () => {
    const hits = files
      .filter((abs) => !PENDING.has(rel(abs)) && RAW_PAGING.test(readFileSync(abs, 'utf8')))
      .map(rel)
    expect(hits).toEqual([])
  })

  it('has no pending entry that already moved', () => {
    const stale = [...PENDING].filter((p) => {
      try {
        return !RAW_PAGING.test(readFileSync(join(ROOT, p), 'utf8'))
      } catch {
        return true
      }
    })
    expect(stale).toEqual([])
  })
})
