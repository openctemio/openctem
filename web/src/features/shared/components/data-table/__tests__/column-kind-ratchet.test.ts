/**
 * Every DataTable column declares what it holds (`meta.kind`): the kind sets
 * its alignment, width and first sort direction, so no page styles a header
 * or a cell. Tables written before kinds existed are listed in
 * column-kind-debt.json with the number of columns still without a kind:
 *
 * - a file that is not listed may define no column without a kind (a NEW
 *   table always declares kinds);
 * - a listed file may not go above its count;
 * - a listed file that went below its count must lower it (regenerate with
 *   UPDATE_COLUMN_KIND_DEBT=1, then review the diff: counts only go down).
 *
 * A column definition is a `header:` property in a file that types columns
 * (`ColumnDef`), inside an object that also has `accessorKey`, `accessorFn`,
 * `cell` or `id` (a CSV export field `{ header, accessor }` is not one); a kind is `kind: '<one of the ColumnKind values>'`. Columns
 * with id `select` / `actions` need no header and take their kind from the id.
 *
 *   UPDATE_COLUMN_KIND_DEBT=1 npx vitest run src/features/shared/components/data-table/__tests__/column-kind-ratchet.test.ts
 */
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'
import { KIND_LAYOUT } from '../column-meta'
import debt from './column-kind-debt.json'

const WEB = join(__dirname, '..', '..', '..', '..', '..', '..')
const ROOTS = [join(WEB, 'src'), join(WEB, 'console', 'src')].filter((d) => existsSync(d))
const DEBT_FILE = join(__dirname, 'column-kind-debt.json')
const SKIP_DIR = new Set(['__tests__', '__mocks__', 'generated', 'dictionaries', 'node_modules'])

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return SKIP_DIR.has(name) ? [] : sources(path)
    if (/\.(test|spec|stories)\.tsx?$/.test(name) || name.endsWith('.d.ts')) return []
    return /\.tsx?$/.test(name) ? [path] : []
  })
}

const KINDS = Object.keys(KIND_LAYOUT).join('|')
const KIND_RE = new RegExp(`\\bkind:\\s*['"](?:${KINDS})['"]`, 'g')

/** The object literal around `at`: from its `{` to its matching `}` (or the text's end). */
function enclosingObject(text: string, at: number): string {
  let depth = 0
  let open = -1
  for (let i = at - 1; i >= 0; i--) {
    const c = text[i]
    if (c === '}') depth++
    else if (c === '{') {
      if (depth === 0) {
        open = i
        break
      }
      depth--
    }
  }
  if (open < 0) return ''
  depth = 0
  for (let i = open; i < text.length; i++) {
    const c = text[i]
    if (c === '{') depth++
    else if (c === '}' && --depth === 0) return text.slice(open, i + 1)
  }
  return text.slice(open)
}

/**
 * A table column: a `header:` in an object that also says what the column
 * reads or draws (`accessorKey`, `accessorFn`, `cell`, `id`). Other objects
 * with a `header` (a CSV export field `{ header, accessor }`) are no column.
 */
const COLUMN_KEY_RE = /\b(?:accessorKey|accessorFn|cell|id):/

/** Columns without a kind, per file that defines DataTable columns. */
function columnKindDebt(text: string): number {
  if (!/\bColumnDef\b/.test(text)) return 0
  const headers = [...text.matchAll(/\bheader:\s/g)].filter((m) =>
    COLUMN_KEY_RE.test(enclosingObject(text, m.index))
  ).length
  const kinds = text.match(KIND_RE)?.length ?? 0
  return Math.max(0, headers - kinds)
}

function census(): Record<string, number> {
  const out: Record<string, number> = {}
  for (const root of ROOTS) {
    for (const file of sources(root)) {
      // The table component itself defines no page's columns.
      if (file.includes('/features/shared/components/data-table/')) continue
      const n = columnKindDebt(readFileSync(file, 'utf8'))
      if (n > 0) out[relative(WEB, file)] = n
    }
  }
  return out
}

const baseline = debt as Record<string, number>

describe('column kind ratchet', () => {
  it('counts a column without a kind, and not one with a kind', () => {
    const cols = `const c: ColumnDef<R>[] = [
      { accessorKey: 'a', header: 'A', meta: { kind: 'name' } },
      { accessorKey: 'b', header: 'B' },
    ]`
    expect(columnKindDebt(cols)).toBe(1)
    expect(
      columnKindDebt(cols.replace("header: 'B' }", "header: 'B', meta: { kind: 'date' } }"))
    ).toBe(0)
    // A kind that is not a column kind does not count.
    expect(columnKindDebt(cols.replace("kind: 'name'", "kind: 'banana'"))).toBe(2)
  })

  it('counts only table columns, not CSV export fields in the same file', () => {
    const text = `const c: ColumnDef<R>[] = [
      { accessorKey: 'a', header: 'A', meta: { kind: 'name' } },
      { id: 'b', header: ({ column }) => <H column={column} />, cell: ({ row }) => row.original.b },
    ]
    const exportFields = [
      { header: 'Name', accessor: (r: R) => r.a },
      { header: 'Owner', accessor: (r: R) => r.b },
    ]`
    // Column b has no kind; the two export fields are not columns.
    expect(columnKindDebt(text)).toBe(1)
  })

  const found = census()

  if (process.env.UPDATE_COLUMN_KIND_DEBT === '1') {
    it('writes the baseline', () => {
      for (const [file, n] of Object.entries(found)) {
        if (baseline[file] !== undefined && n > baseline[file]) {
          throw new Error(
            `${file}: ${n} columns without a kind, more than the ${baseline[file]} allowed`
          )
        }
        if (baseline[file] === undefined && Object.keys(baseline).length > 0) {
          throw new Error(`${file}: a new table must declare meta.kind on every column`)
        }
      }
      const sorted = Object.fromEntries(
        Object.entries(found).sort(([a], [b]) => a.localeCompare(b))
      )
      writeFileSync(DEBT_FILE, `${JSON.stringify(sorted, null, 2)}\n`)
    })
    return
  }

  it('no new table defines a column without a kind', () => {
    const fresh = Object.entries(found)
      .filter(([file]) => baseline[file] === undefined)
      .map(([file, n]) => `${file}: ${n}`)
    expect(fresh, 'declare meta.kind on every column (see column-meta.ts)').toEqual([])
  })

  it('no listed table gains a column without a kind', () => {
    const grown = Object.entries(found)
      .filter(([file, n]) => baseline[file] !== undefined && n > baseline[file])
      .map(([file, n]) => `${file}: ${n} > ${baseline[file]}`)
    expect(grown).toEqual([])
  })

  it('a table that gained kinds lowers its count (UPDATE_COLUMN_KIND_DEBT=1)', () => {
    const stale = Object.entries(baseline)
      .filter(([file, n]) => (found[file] ?? 0) < n)
      .map(([file, n]) => `${file}: ${found[file] ?? 0} < ${n}`)
    expect(stale).toEqual([])
  })
})
