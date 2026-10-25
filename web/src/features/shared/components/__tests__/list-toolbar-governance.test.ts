/**
 * Governance: one list toolbar (research/267).
 *
 * Every list draws its toolbar through `ListToolbar` (directly, or through
 * `DataTable`, which renders it), and its search box through `ListSearch`.
 * Before this, 40-odd lists hand-built their own search field (each with its
 * own width, height, icon spacing and placeholder style) and the filter
 * trigger sat flush against the search on one page and 8px away on the next.
 *
 * Rules, over every .tsx file of the app and the admin console (tests
 * excluded):
 *
 *   1. No raw search field: an `<Input>` whose props say "search" (a
 *      placeholder or aria-label key/text with "search", or `type="search"`)
 *      is drawn only by list-search.tsx. A list passes `search` to
 *      `DataTable` / `ListToolbar`, or renders `ListSearch`. Pickers inside a
 *      dialog are listed in `RAW_SEARCH_ALLOWED` with the reason; that list
 *      can only shrink.
 *   2. The filter panel trigger (`FilterPanelToggle`) is drawn by DataTable
 *      (`filterToggle`) or passed as `ListToolbar`'s `filter`; pages do not
 *      place it themselves, so it always sits joined to the search.
 *   3. Joining the trigger to the search is ListSearch's job: no other file
 *      squares off the trigger's corners (`[data-slot=filter-button]` with
 *      `rounded-e-none`).
 */
import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

const WEB = join(__dirname, '..', '..', '..', '..', '..')
const ROOTS = [join(WEB, 'src'), join(WEB, 'console', 'src')]

function walk(path: string, out: string[]) {
  let st
  try {
    st = statSync(path)
  } catch {
    return
  }
  if (st.isDirectory()) {
    for (const name of readdirSync(path)) {
      if (name === 'node_modules' || name === '__tests__' || name.startsWith('.')) continue
      walk(join(path, name), out)
    }
  } else if (path.endsWith('.tsx') && !/\.test\.tsx$/.test(path)) {
    out.push(path)
  }
}

const files: string[] = []
for (const root of ROOTS) walk(root, files)
const rel = (abs: string) => relative(WEB, abs).split(sep).join('/')

/**
 * Search fields that are not a list toolbar: a picker or lookup inside a
 * dialog, sheet or popover, sized to that surface. file -> reason.
 */
const RAW_SEARCH_ALLOWED: Record<string, string> = {}

/** Files that may render `FilterPanelToggle` / `FilterButton` themselves. file -> reason. */
const TRIGGER_ALLOWED: Record<string, string> = {
  'src/features/shared/components/filter-button.tsx': 'defines it',
  'src/features/shared/components/data-table/data-table.tsx': 'renders filterToggle',
}

/** Each `<Input ...>` element's props, up to its end. */
function inputBlocks(src: string): { line: number; props: string }[] {
  const out: { line: number; props: string }[] = []
  const re = /<Input(\s|$)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(src))) {
    let depth = 0
    let end = m.index
    for (let i = m.index; i < src.length && i < m.index + 3000; i++) {
      const c = src[i]
      if (c === '{') depth++
      else if (c === '}') depth--
      else if (c === '>' && depth === 0) {
        end = i
        break
      }
    }
    out.push({ line: src.slice(0, m.index).split('\n').length, props: src.slice(m.index, end) })
  }
  return out
}

const SEARCH_PROP =
  /(placeholder|aria-label)=\{?\s*(t\(\s*)?['"`][^'"`]*search[^'"`]*['"`]|type=["']search["']/i

describe('one list toolbar', () => {
  it('draws every search field through ListSearch (no raw search Input)', () => {
    const offenders: string[] = []
    for (const f of files) {
      const r = rel(f)
      if (r === 'src/features/shared/components/list-search.tsx' || RAW_SEARCH_ALLOWED[r]) continue
      for (const { line, props } of inputBlocks(readFileSync(f, 'utf8'))) {
        if (SEARCH_PROP.test(props)) offenders.push(`${r}:${line}`)
      }
    }
    expect(offenders).toEqual([])
  })

  it('keeps the raw-search allowlist honest (every entry still has a raw search field)', () => {
    const stale = Object.keys(RAW_SEARCH_ALLOWED).filter((r) => {
      const f = files.find((x) => rel(x) === r)
      if (!f) return true
      return !inputBlocks(readFileSync(f, 'utf8')).some(({ props }) => SEARCH_PROP.test(props))
    })
    expect(stale).toEqual([])
  })

  it('places the filter panel trigger only through DataTable filterToggle or ListToolbar filter', () => {
    const offenders: string[] = []
    for (const f of files) {
      const r = rel(f)
      if (TRIGGER_ALLOWED[r]) continue
      const src = readFileSync(f, 'utf8')
      if (/<FilterPanelToggle[\s>]/.test(src)) offenders.push(`${r}: FilterPanelToggle`)
      // A bare FilterButton is fine as the toolbar's `filter` (a sheet
      // trigger); anywhere else it is a trigger outside the toolbar.
      if (/<FilterButton[\s>]/.test(src) && !/\bfilter=\{/.test(src)) {
        offenders.push(`${r}: FilterButton outside ListToolbar filter`)
      }
    }
    expect(offenders).toEqual([])
  })

  it('leaves joining the trigger to the search to ListSearch', () => {
    const offenders = files
      .filter((f) => rel(f) !== 'src/features/shared/components/list-search.tsx')
      .filter((f) => /\[data-slot=filter-button\]\]:rounded-e-none/.test(readFileSync(f, 'utf8')))
      .map(rel)
    expect(offenders).toEqual([])
  })

  it('finds the files it checks', () => {
    const lists = files.filter((f) => /<DataTable[\s>]/.test(readFileSync(f, 'utf8')))
    expect(lists.length).toBeGreaterThan(80)
  })
})
