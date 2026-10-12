/**
 * Code that must stay out of first-load JS.
 *
 * Each entry is a module that every visit (the root providers, the dashboard
 * shell) or the default dashboard view loads, and a heavy dependency it must
 * not import statically. They were measured on a production build
 * (research/29-ui-performance.md): zod in the root providers (~90 KB gzipped
 * on every page), cmdk in the shell (~25 KB on every dashboard page), and
 * recharts / @dnd-kit in the dashboard's first load (~145 KB). Load them with
 * next/dynamic (or a narrower import) instead, as the files below do.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = join(process.cwd(), 'src')

/** Static `import ... from '<spec>'` lines (type-only imports excluded). */
function staticImports(file: string): string[] {
  const text = readFileSync(join(SRC, file), 'utf8')
  const specs: string[] = []
  for (const m of text.matchAll(/^import\s+(?!type\s)[^;]*?from\s+['"]([^'"]+)['"]/gm)) {
    specs.push(m[1])
  }
  return specs
}

const RULES: { file: string; forbidden: RegExp; why: string }[] = [
  {
    file: 'app/providers.tsx',
    forbidden: /^zod$/,
    why: "root providers: use config from 'zod/v4/core', not z from 'zod'",
  },
  {
    file: 'context/search-provider.tsx',
    forbidden: /command-menu$/,
    why: 'dashboard shell: the command palette loads on first open',
  },
  {
    file: 'app/(dashboard)/page.tsx',
    forbidden: /(classic-dashboard|dashboard-canvas|dashboard-canvas-editor)$/,
    why: 'dashboard: only the default CTEM view is in the first load',
  },
  {
    file: 'features/dashboard/components/ctem-dashboard.tsx',
    forbidden: /analyst-detail$/,
    why: 'CTEM dashboard: the analyst charts load after the cards',
  },
  {
    file: 'features/dashboard/components/ctem/exposure-hero.tsx',
    forbidden: /^@\/components\/charts$|^recharts$/,
    why: 'CTEM card: its chart comes from trend-charts via next/dynamic',
  },
  {
    file: 'features/dashboard/components/ctem/priority-over-time.tsx',
    forbidden: /^@\/components\/charts$|^recharts$/,
    why: 'CTEM card: its chart comes from trend-charts via next/dynamic',
  },
]

describe('first-load bundle boundaries', () => {
  it.each(RULES)('$file keeps $forbidden out of its static imports', ({ file, forbidden, why }) => {
    const offending = staticImports(file).filter((spec) => forbidden.test(spec))
    expect(offending, why).toEqual([])
  })

  it('the import scanner sees real imports', () => {
    // Guards the regex itself: a file known to import next/dynamic.
    expect(staticImports('context/search-provider.tsx')).toContain('next/dynamic')
  })
})
