/**
 * Governance: every modal surface uses the shared frame of
 * components/ui/modal-layout.tsx — a fixed header, a body that is the only
 * scroll container, a fixed footer. Dialogs used to put `max-h-[90vh]
 * overflow-y-auto` on the whole content, so the title, the close button and
 * the actions scrolled away with the fields (worst on a phone). This test
 * fails when:
 *
 *   - a DialogContent / AlertDialogContent / SheetContent sets its own scroll
 *     or layout (`overflow-*`, `max-h-*`, `flex`, `grid`, `p-0`, `gap-*`), or a
 *     DialogContent / AlertDialogContent its own width (`max-w-*`: use `size`);
 *   - a surface has no Header, or has content outside its Body (anything
 *     but Header, Body and Footer, looking through one wrapping form).
 */
import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import ts from 'typescript'

const SRC = join(__dirname, '../../..')

/** Surfaces with their own, reviewed frame. Never add a form dialog here. */
const EXEMPT = new Set([
  // The command palette: a search field and a list, no header or footer.
  'components/ui/command.tsx',
  // The mobile sidebar is a navigation drawer, not a modal with actions.
  'components/ui/sidebar.tsx',
  // The entity detail drawer frame (pinned header, scrolling body, footer
  // portal) shared by every detail sheet.
  'features/shared/components/detail-sheet-layout.tsx',
])

/**
 * Components that render a surface's Body and Footer themselves (a form whose
 * steps scroll and whose actions are pinned), placed directly in a Content.
 */
const RENDERS_BODY = new Set(['ScanWorkflowForm'])

/**
 * Files not migrated yet, moved onto the frame by area. The migrations leave
 * this list alone (so they do not conflict with each other); the last one
 * empties it, and then every file is checked. Never add an entry.
 */
const PENDING = new Set<string>([
  'features/scans/components/edit-scan-dialog.tsx',
  'features/scans/components/new-scan/new-scan-dialog.tsx',
  'features/scans/components/quick-scan-dialog.tsx',
  'features/scans/components/scan-assets-dialog.tsx',
])

function* tsxFiles(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (name === 'node_modules' || name === '__tests__') continue
    if (statSync(p).isDirectory()) yield* tsxFiles(p)
    else if (name.endsWith('.tsx') && !name.endsWith('.test.tsx')) yield p
  }
}

const SURFACES: Record<string, string> = {
  DialogContent: 'Dialog',
  SheetContent: 'Sheet',
  AlertDialogContent: 'AlertDialog',
}

// A class token, with any variant prefix (`sm:max-w-lg`).
const token = (body: string) =>
  new RegExp(`(?:^|[\\s'"\`])((?:[\\w-]+:)*(?:${body}))(?=$|[\\s'"\`])`)
const LAYOUT_CLASS = token(
  'overflow(?:-[xy])?-\\w+|max-h-[^\\s\'"`]+|flex|grid|p-0|gap-[^\\s\'"`]+'
)
const WIDTH_CLASS = token('max-w-[^\\s\'"`]+')

function tagOf(n: ts.Node): string | null {
  if (ts.isJsxElement(n)) return n.openingElement.tagName.getText()
  if (ts.isJsxSelfClosingElement(n)) return n.tagName.getText()
  if (ts.isJsxFragment(n)) return '<>'
  return null
}

function hasTag(n: ts.Node, name: string): boolean {
  if (tagOf(n) === name) return true
  return ts.forEachChild(n, (c) => (hasTag(c, name) ? true : undefined)) ?? false
}

function meaningful(children: ts.NodeArray<ts.JsxChild>) {
  return children.filter((c) =>
    ts.isJsxText(c) ? c.getText().trim() !== '' : ts.isJsxExpression(c) ? !!c.expression : true
  )
}

/**
 * Is there content outside Header / Body / Footer? Looks at the content's
 * children, through one wrapping `<form>`, react-hook-form `<Form>` or
 * fragment, as the body sits there.
 */
function looseContent(el: ts.JsxElement, P: string): boolean {
  let level = el.children
  for (let depth = 0; depth < 4; depth++) {
    const m = meaningful(level)
    // A branch that renders the body or the footer (`{cond ? <Body>…</Body> :
    // null}`, `{tab === 'new' && <Footer>…</Footer>}`) is fine.
    const rest = m.filter(
      (c) =>
        ![`${P}Header`, `${P}Footer`, `${P}Body`].includes(tagOf(c) ?? '') &&
        !RENDERS_BODY.has(tagOf(c) ?? '') &&
        !(ts.isJsxExpression(c) && (hasTag(c, `${P}Body`) || hasTag(c, `${P}Footer`)))
    )
    const wrapper =
      rest.length === 1 && ['form', 'Form', '<>', `${P}Form`].includes(tagOf(rest[0]) ?? '')
    if (wrapper && (ts.isJsxElement(rest[0]) || ts.isJsxFragment(rest[0]))) {
      level = (rest[0] as ts.JsxElement | ts.JsxFragment).children
      continue
    }
    return rest.length > 0
  }
  return false
}

function classText(el: ts.JsxElement): string {
  const attr = el.openingElement.attributes.properties.find(
    (a) => ts.isJsxAttribute(a) && a.name.getText() === 'className'
  ) as ts.JsxAttribute | undefined
  if (!attr?.initializer) return ''
  // Every string literal in the value (a plain string, or the parts of cn(...)).
  const parts: string[] = []
  const visit = (n: ts.Node) => {
    if (ts.isStringLiteralLike(n)) parts.push(n.text)
    ts.forEachChild(n, visit)
  }
  if (ts.isStringLiteral(attr.initializer)) parts.push(attr.initializer.text)
  else visit(attr.initializer)
  return parts.join(' ')
}

/** What is wrong with one file's modal surfaces (empty: nothing). */
function problems(src: string): string[] {
  const sf = ts.createSourceFile('x.tsx', src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const out: string[] = []
  const visit = (n: ts.Node) => {
    if (ts.isJsxElement(n) && SURFACES[n.openingElement.tagName.getText()]) {
      const tag = n.openingElement.tagName.getText()
      const P = SURFACES[tag]
      const value = classText(n)
      const layout = value.match(LAYOUT_CLASS)
      if (layout) out.push(`${tag} sets "${layout[1]}" (the frame owns scroll and layout)`)
      if (tag !== 'SheetContent') {
        const width = value.match(WIDTH_CLASS)
        if (width) out.push(`${tag} sets "${width[1]}" (use size="sm|md|lg|xl|full")`)
      }
      if (!hasTag(n, `${P}Header`)) out.push(`${tag} without ${P}Header`)
      if (looseContent(n, P)) out.push(`${tag} has content outside ${P}Body`)
    }
    ts.forEachChild(n, visit)
  }
  visit(sf)
  return out
}

// Parsing every .tsx file takes a few seconds on a busy runner.
describe('modal surfaces', { timeout: 60_000 }, () => {
  const files = [...tsxFiles(SRC)].map((f) => ({
    rel: relative(SRC, f),
    src: readFileSync(f, 'utf8'),
  }))

  it('use the shared header / body / footer frame', () => {
    const offenders: string[] = []
    for (const { rel, src } of files) {
      if (EXEMPT.has(rel) || PENDING.has(rel)) continue
      if (rel.startsWith('components/ui/')) continue
      for (const p of problems(src)) offenders.push(`${rel}: ${p}`)
    }
    expect(offenders).toEqual([])
  })

  it('lists only files that exist', () => {
    const paths = new Set(files.map((f) => f.rel))
    expect([...PENDING].filter((rel) => !paths.has(rel))).toEqual([])
  })

  it('catches the patterns it is meant to catch', () => {
    expect(
      problems(
        '<DialogContent className="sm:max-w-lg max-h-[90vh] overflow-y-auto"><DialogHeader/><p/></DialogContent>'
      )
    ).toEqual([
      'DialogContent sets "max-h-[90vh]" (the frame owns scroll and layout)',
      'DialogContent sets "sm:max-w-lg" (use size="sm|md|lg|xl|full")',
      'DialogContent has content outside DialogBody',
    ])
    expect(
      problems(
        '<DialogContent size="lg"><DialogHeader/><DialogForm><DialogBody/><DialogFooter/></DialogForm></DialogContent>'
      )
    ).toEqual([])
    // A confirmation with nothing between header and footer needs no body.
    expect(problems('<DialogContent><DialogHeader/><DialogFooter/></DialogContent>')).toEqual([])
    // Fields in a form between header and footer still count.
    expect(
      problems('<DialogContent><DialogHeader/><form><input/><DialogFooter/></form></DialogContent>')
    ).toEqual(['DialogContent has content outside DialogBody'])
    expect(
      problems(
        '<AlertDialogContent><AlertDialogHeader/>{x ? <AlertDialogBody/> : null}</AlertDialogContent>'
      )
    ).toEqual([])
    expect(
      problems('<DialogContent><DialogHeader/><DialogBody/>{x && <DialogFooter/>}</DialogContent>')
    ).toEqual([])
    expect(problems('<SheetContent className="w-full sm:max-w-xl"><p/></SheetContent>')).toEqual([
      'SheetContent without SheetHeader',
      'SheetContent has content outside SheetBody',
    ])
    expect(
      problems(
        '<SheetContent className={cn("flex flex-col p-0", x)}><SheetHeader/></SheetContent>'
      )[0]
    ).toContain('"flex"')
  })
})
