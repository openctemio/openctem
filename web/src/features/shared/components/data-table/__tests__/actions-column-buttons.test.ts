import { readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * The `actions` column is 48 px wide: room for the row menu or one icon
 * button. A labelled button or link there ("Cancel", "Block", "Approve",
 * "Manage") was cut at the frame's edge (scan detail runs, console AI
 * applications, Settings > Integrations). A column of labelled controls says
 * `kind: 'decisions'`, which is as wide as its controls.
 *
 * The scan reads every column whose id is `actions` (either quote), and
 * every column that says `kind: 'actions'`, and counts a `<Button>` that is
 * not an icon button and a `<Link>` / `<a>` with text in it. The browser
 * check that measures the result is the layout-break detector (spec 75).
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
export function actionColumns(src: string): string[] {
  const out: string[] = []
  for (const m of src.matchAll(/^( *)id: ['"]actions['"],$/gm)) {
    const indent = m[1].length - 2
    const rest = src.slice(m.index! + m[0].length)
    const end = rest.search(new RegExp(`^ {${indent}}\\}\\)?,?$`, 'm'))
    out.push(end < 0 ? rest : rest.slice(0, end))
  }
  return out
}

/** A labelled control in a column's source: a button that is not an icon button, or a link with text. */
export function labelledControls(col: string): string[] {
  const found: string[] = []
  for (const b of col.matchAll(/<Button\b((?:=>|[^>])*)>/g)) {
    if (!/size=["{]['"]?icon/.test(b[1])) found.push('Button')
  }
  for (const l of col.matchAll(/<(Link|a)\b((?:=>|[^>])*)>([\s\S]*?)<\/\1>/g)) {
    // Text in the link: a translated label or plain words, not only an icon.
    // Split on tags instead of stripping them, so no half-removed tag can remain.
    const pieces = l[3].split(/<[^>]*>/)
    if (pieces.some((p) => /\{t\(/.test(p) || /^\s*[A-Za-z][^{]*$/m.test(p))) found.push(l[1])
  }
  return found
}

/** True when the column is wide enough by its own say: a decisions column or an explicit width. */
export function declaresWidth(col: string): boolean {
  return /kind: '(decisions)'|\bwidth: /.test(col)
}

describe('actions column', () => {
  it('holds no labelled button or link unless the column is a decisions column', () => {
    const offenders: string[] = []
    for (const root of ROOTS) {
      for (const f of files(root)) {
        const src = readFileSync(f, 'utf8')
        if (!/id: ['"]actions['"]/.test(src)) continue
        for (const col of actionColumns(src)) {
          if (declaresWidth(col)) continue
          if (labelledControls(col).length) offenders.push(path.relative(WEB, f))
        }
      }
    }
    expect(offenders).toEqual([])
  })

  it('finds a labelled button or link in either quote style, and passes icon buttons', () => {
    const col = (body: string, quote = "'") =>
      `    {\n      id: ${quote}actions${quote},\n      cell: () => (\n${body}\n      ),\n    },\n`
    const manage = `<Button variant="ghost" size="sm" asChild><Link href="/x">{t('a.manage', 'Manage')}</Link></Button>`
    const bare = `<Link href="/x">Manage</Link>`
    const icon = `<Button variant="ghost" size="icon" aria-label="Open"><Eye /></Button>`
    const iconLink = `<Link href="/x" aria-label="Open"><Eye className="h-4 w-4" /></Link>`
    expect(labelledControls(actionColumns(col(manage, '"'))[0]).length).toBeGreaterThan(0)
    expect(labelledControls(bare).length).toBeGreaterThan(0)
    expect(labelledControls(icon)).toEqual([])
    expect(labelledControls(iconLink)).toEqual([])
    expect(declaresWidth("meta: { kind: 'decisions' },")).toBe(true)
    expect(declaresWidth('meta: { width: 120 },')).toBe(true)
    expect(declaresWidth(manage)).toBe(false)
  })
})
