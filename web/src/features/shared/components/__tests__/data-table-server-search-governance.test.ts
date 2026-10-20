/**
 * Governance: a server-paged DataTable (`manualPagination`) says what its
 * search box does. The built-in search box filters the rows already loaded, so
 * on a server-paged list it searches one page and silently hides matches on the
 * others (the approvals page shipped that way). Such a table passes
 * `showSearch={false}` and puts a server search (the list's `q`) in
 * `toolbarStart`, or passes `showSearch` explicitly after review.
 */
import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SRC = join(__dirname, '../../../..')

function* tsxFiles(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (name === 'node_modules' || name === '__tests__') continue
    if (statSync(p).isDirectory()) yield* tsxFiles(p)
    else if (name.endsWith('.tsx')) yield p
  }
}

/** The props of each `<DataTable ...>` element: up to its closing `/>` at the same indent. */
function dataTableBlocks(src: string): { line: number; props: string }[] {
  const lines = src.split('\n')
  const out: { line: number; props: string }[] = []
  lines.forEach((l, i) => {
    if (!/<DataTable(\s|$)/.test(l)) return
    const indent = l.length - l.trimStart().length
    const end = new RegExp(`^\\s{${indent}}/>\\s*$`)
    const block: string[] = [l]
    if (!l.trimEnd().endsWith('/>')) {
      for (let j = i + 1; j < Math.min(lines.length, i + 150); j++) {
        block.push(lines[j])
        if (end.test(lines[j])) break
      }
    }
    out.push({ line: i + 1, props: block.join('\n') })
  })
  return out
}

describe('server-paged DataTable search', () => {
  it('sets showSearch on every DataTable with manualPagination', () => {
    const offenders: string[] = []
    for (const file of tsxFiles(SRC)) {
      for (const { line, props } of dataTableBlocks(readFileSync(file, 'utf8'))) {
        if (props.includes('manualPagination') && !props.includes('showSearch')) {
          offenders.push(`${relative(SRC, file)}:${line}`)
        }
      }
    }
    expect(offenders).toEqual([])
  })

  it('finds the server-paged tables it checks', () => {
    let n = 0
    for (const file of tsxFiles(SRC)) {
      n += dataTableBlocks(readFileSync(file, 'utf8')).filter((b) =>
        b.props.includes('manualPagination')
      ).length
    }
    expect(n).toBeGreaterThan(20)
  })
})
