/**
 * Code that must stay out of first-load JS.
 *
 * Each entry is a module that every visit (the root providers, the dashboard
 * shell) or the default dashboard view loads, and a heavy dependency it must
 * not import statically. They were measured on a production build
 * (research/29-ui-performance.md): zod in the root providers (~90 KB gzipped
 * on every page), cmdk in the shell (~25 KB on every dashboard page), and
 * @dnd-kit in the dashboard's first load. Load them with
 * next/dynamic (or a narrower import) instead, as the files below do.
 */
import { readdirSync, readFileSync } from 'node:fs'
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
    forbidden: /dashboard-editor$|^@dnd-kit\//,
    why: 'dashboard: the editor and its drag and drop kit load when Customize opens',
  },
  {
    file: 'features/dashboards/components/dashboard-home.tsx',
    forbidden: /dashboard-editor$|^@dnd-kit\//,
    why: 'dashboard home: the editor and its drag and drop kit load when Customize opens',
  },
  {
    file: 'components/entry/entry-frame.tsx',
    forbidden: /dropdown-menu$|language-switcher$|entry-language-menu$/,
    why: 'pages without the app shell: the language menu loads after the page renders',
  },
  {
    file: 'features/shared/components/section-tabs.tsx',
    forbidden: /\/ui\/tabs$/,
    why: "route-link tabs (legal pages too): import the strip from '@/components/ui/tab-strip', not the tabs primitive",
  },
  {
    file: 'features/account/components/ownership-invitations-card.tsx',
    forbidden: /^@\/features\/shared$|^@\/components\/layout$/,
    why: 'a page without the app shell: import shared parts by their own module, not the barrel',
  },
  {
    file: 'features/ci-runners/components/ci-github-callback.tsx',
    forbidden: /^@\/features\/shared$|^@\/components\/layout$/,
    why: 'a one-step callback page: import shared parts by their own module, not the barrel',
  },
]

describe('first-load bundle boundaries', () => {
  it.each(RULES)('$file keeps $forbidden out of its static imports', ({ file, forbidden, why }) => {
    const offending = staticImports(file).filter((spec) => forbidden.test(spec))
    expect(offending, why).toEqual([])
  })

  it('package.json lets the bundler drop unused re-exports of the barrels', () => {
    // Without "sideEffects" every module behind `export *` in a barrel such as
    // '@/features/shared' is kept, used or not: a page importing one badge
    // downloaded the data table, the filter kit and the sheets. A module that
    // works only by being imported (a registration, a style sheet) must be
    // listed here or it is dropped.
    const pkg = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8'))
    expect(pkg.sideEffects).toEqual(expect.arrayContaining(['*.css']))
    expect(pkg.sideEffects).toContain('./src/features/findings/config/register-layouts.ts')
  })

  it('every side-effect-only import in src is listed in package.json sideEffects', () => {
    const pkg = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8'))
    const listed: string[] = pkg.sideEffects
    const offending: string[] = []
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const name = entry.name
        const path = join(dir, name)
        if (entry.isDirectory()) {
          if (name !== '__tests__' && name !== 'test' && name !== 'node_modules') walk(path)
          continue
        }
        if (!/\.(ts|tsx)$/.test(name) || /\.test\.tsx?$/.test(name)) continue
        for (const m of readFileSync(path, 'utf8').matchAll(
          /^import\s+['"](@\/[^'"]+|\.[^'"]+)['"]/gm
        )) {
          const spec = m[1]
          if (spec.endsWith('.css')) continue
          const target = './src/' + spec.replace(/^@\//, '') + '.ts'
          if (!listed.includes(target)) offending.push(`${path}: ${spec}`)
        }
      }
    }
    walk(SRC)
    expect(offending, 'add the module to "sideEffects" in package.json').toEqual([])
  })

  it('the import scanner sees real imports', () => {
    // Guards the regex itself: a file known to import next/dynamic.
    expect(staticImports('context/search-provider.tsx')).toContain('next/dynamic')
  })
})
