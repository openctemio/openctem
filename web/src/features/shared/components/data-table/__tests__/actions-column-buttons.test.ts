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
 * not an icon button, an icon-sized button that still shows a label (a label
 * hidden only on phones, `max-sm:sr-only`, shows on a desktop: proxy pools
 * "Reset health" sat over the enable switch), a `<Link>` / `<a>` with text
 * in it, and more than one control (a switch beside a button). A component
 * of the same file that the cell renders is read as part of the column. The
 * browser check that measures the result is the layout-break detector
 * (spec 75).
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

/** The text of an element body with `sr-only` pieces (hidden at every width) left out. */
function visibleText(body: string): string[] {
  const pieces: string[] = []
  // Walk the tags and the text between them in order; nothing is stripped, so
  // no half-removed tag can remain. Text inside an sr-only element is skipped.
  let hiddenTag = ''
  let depth = 0
  for (const token of body.split(/(<[^>]*>)/)) {
    const tag = /^<(\/?)(\w+)/.exec(token)
    if (!tag) {
      if (!hiddenTag) pieces.push(token)
      continue
    }
    const closing = tag[1] === '/'
    const selfClosing = token.endsWith('/>')
    if (hiddenTag) {
      if (tag[2] !== hiddenTag || selfClosing) continue
      depth += closing ? -1 : 1
      if (depth === 0) hiddenTag = ''
    } else if (!closing && !selfClosing && /className="sr-only"/.test(token)) {
      hiddenTag = tag[2]
      depth = 1
    }
  }
  return pieces
}

function hasLabel(pieces: string[]): boolean {
  return pieces.some((p) => /\{t\(/.test(p) || /^\s*[A-Za-z][^{]*$/m.test(p))
}

/** A labelled control in a column's source: a button that is not an icon button, or a link with text. */
export function labelledControls(col: string): string[] {
  const found: string[] = []
  for (const b of col.matchAll(
    /<Button\b((?:=>|[^>])*)>([\s\S]*?)<\/Button>|<Button\b((?:=>|[^>])*)\/>/g
  )) {
    const attrs = b[1] ?? b[3] ?? ''
    const icon = /size=["{]['"]?icon/.test(attrs)
    if (!icon) found.push('Button')
    else if (b[2] !== undefined && !/\basChild\b/.test(attrs) && hasLabel(visibleText(b[2])))
      found.push('icon Button with a label')
  }
  for (const l of col.matchAll(/<(Link|a)\b((?:=>|[^>])*)>([\s\S]*?)<\/\1>/g)) {
    // Text in the link: a translated label or plain words, not only an icon.
    if (hasLabel(visibleText(l[3]))) found.push(l[1])
  }
  // Two controls do not fit the menu-sized column either.
  const controls = col.match(/<(Button|Switch|Checkbox|Link|a)\b/g) ?? []
  const asChildLinks = (col.match(/<Button\b[^>]*\basChild\b/g) ?? []).length
  if (controls.length - asChildLinks > 1) found.push(`${controls.length - asChildLinks} controls`)
  return found
}

/**
 * The column with the bodies of the components of the same file it renders
 * (`<RowActions ... />` defined as `function RowActions(`), one level deep:
 * a labelled button inside one is as wide as one written in the cell.
 */
export function withLocalComponents(col: string, src: string): string {
  let out = col
  for (const name of new Set([...col.matchAll(/<([A-Z]\w+)\b/g)].map((m) => m[1]))) {
    const def = src.match(new RegExp(`^(?:export )?function ${name}\\b[\\s\\S]*?^\\}`, 'm'))
    if (def) out += '\n' + def[0]
  }
  return out
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
          const found = labelledControls(withLocalComponents(col, src))
          if (found.length) offenders.push(`${path.relative(WEB, f)}: ${found.join(', ')}`)
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

  it('finds an icon button that shows a label, two controls, and a local row component', () => {
    const labelled = `<Button variant="ghost" size="icon-sm" aria-label="Reset"><RotateCcw /><span className="max-sm:sr-only">{t('p.reset', 'Reset health')}</span></Button>`
    const hidden = `<Button variant="ghost" size="icon-sm"><RotateCcw /><span className="sr-only">{t('p.reset', 'Reset')}</span></Button>`
    expect(labelledControls(labelled)).toContain('icon Button with a label')
    expect(labelledControls(hidden)).toEqual([])
    expect(labelledControls(`<Switch checked />${hidden}`)).toEqual(['2 controls'])
    const src = `function RowActions() {\n  return <Button variant="outline">{t('x.y', 'Retry')}</Button>\n}\n`
    expect(labelledControls(withLocalComponents('<RowActions row={r} />', src))).toEqual(['Button'])
  })
})
