/**
 * A failed load must never look like an empty page. Without an error state a
 * failed fetch leaves `data` undefined and the page renders its empty state or
 * zeros, telling the user "nothing here" when the truth is "we could not find
 * out".
 *
 * This guard reads every route page (`app/**\/page.tsx`). A page that reads
 * data through a hook (`const { data, ... } = useX(...)`, or `useSWR`) must show
 * a failed read: `ErrorState`, a dashboard `WidgetError`, an `AccessNotice`, or
 * an `error={...}` prop on a DataTable or similar shared component.
 *
 * - a page that is not in route-error-state-debt.json must render one;
 * - a listed page that now renders one (or no longer reads data, or is gone)
 *   must be removed from the list, so the list only shrinks.
 *
 * Pages that read nothing themselves (all fetching lives in child components)
 * are outside this guard; each of those components is covered where it fetches.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'
import debt from './route-error-state-debt.json'

const APP = join(__dirname, '..', '..', 'app')

// `const { data, error, isLoading, stats } = useSomething(...)`
const READS_DATA = /const\s*\{[^}]*\b(data|isLoading|stats|error)\b[^}]*\}\s*=\s*use[A-Z]\w*/
const USES_SWR = /\buseSWR\b/
const SHOWS_FAILURE = /ErrorState|WidgetError|AccessNotice|NoAccessState|\b[eE]rror=\{|\bisError\b/

function pages(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : pages(path)
    return name === 'page.tsx' ? [path] : []
  })
}

function readsData(source: string): boolean {
  return READS_DATA.test(source) || USES_SWR.test(source)
}

function showsFailure(source: string): boolean {
  return SHOWS_FAILURE.test(source)
}

const fetching = new Map<string, boolean>()
for (const file of pages(APP)) {
  const src = readFileSync(file, 'utf8')
  if (readsData(src)) fetching.set(relative(APP, file), showsFailure(src))
}

describe('route pages that fetch render an error state', () => {
  it('the detector tells a handled page from an unhandled one', () => {
    const unhandled = `const { data, isLoading } = useThings()\nreturn data ? <A/> : <Empty/>`
    const handled = `const { data, error, mutate } = useThings()\nif (error) return <ErrorState title="x" error={error} onRetry={mutate} />`
    const table = `const { data, error } = useThings()\nreturn <DataTable error={error} />`
    expect(readsData(unhandled) && !showsFailure(unhandled)).toBe(true)
    expect(readsData(handled) && showsFailure(handled)).toBe(true)
    expect(readsData(table) && showsFailure(table)).toBe(true)
    expect(readsData('export default function P() { return <Child /> }')).toBe(false)
  })

  it('every fetching page outside the debt list shows a failed load', () => {
    const missing = [...fetching]
      .filter(([page, ok]) => !ok && !debt.pages.includes(page))
      .map(([page]) => page)
    expect(
      missing,
      'These pages read data but never render ErrorState (or a DataTable error): a failed fetch would look like an empty page. Render ErrorState with Retry.'
    ).toEqual([])
  })

  it('the debt list only holds pages that still lack an error state', () => {
    const stale = debt.pages.filter((page) => fetching.get(page) !== false)
    expect(
      stale,
      'These pages now render an error state (or are gone): remove them from route-error-state-debt.json.'
    ).toEqual([])
  })

  it('the debt list is sorted and has no duplicates', () => {
    expect(debt.pages).toEqual([...new Set(debt.pages)].sort())
  })
})
