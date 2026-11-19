import { readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * The `actions` column is 48 px wide: room for the row menu or one icon
 * button. A labelled button there ("Cancel", "Block", "Approve") was cut at
 * the frame's edge (scan detail runs, console AI applications). A column of
 * labelled buttons says `kind: 'decisions'`, which is as wide as its buttons.
 */

const WEB = path.resolve(__dirname, '../../../../../..')
const ROOTS = ['src', 'console/src'].map((r) => path.join(WEB, r))

function files(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name)
    if (name === '__tests__' || name === 'node_modules') continue
    if (statSync(p).isDirectory()) files(p, out)
    else if (p.endsWith('.tsx')) out.push(p)
  }
  return out
}

/** The column object that starts with `id: 'actions'`: up to its closing brace at the same indent. */
function actionColumns(src: string): string[] {
  const out: string[] = []
  for (const m of src.matchAll(/^( *)id: 'actions',$/gm)) {
    const indent = m[1].length - 2
    const rest = src.slice(m.index! + m[0].length)
    const end = rest.search(new RegExp(`^ {${indent}}\\}\\)?,?$`, 'm'))
    out.push(end < 0 ? rest : rest.slice(0, end))
  }
  return out
}

describe('actions column', () => {
  it('holds no labelled button unless the column is a decisions column', () => {
    const offenders: string[] = []
    for (const root of ROOTS) {
      for (const f of files(root)) {
        const src = readFileSync(f, 'utf8')
        if (!src.includes("id: 'actions'")) continue
        for (const col of actionColumns(src)) {
          if (/kind: '(decisions)'|\bwidth: /.test(col)) continue
          const labelled = [...col.matchAll(/<Button\b((?:=>|[^>])*)>/g)].filter(
            (b) => !/size=["{]['"]?icon/.test(b[1])
          )
          if (labelled.length) offenders.push(path.relative(WEB, f))
        }
      }
    }
    expect(offenders).toEqual([])
  })
})
