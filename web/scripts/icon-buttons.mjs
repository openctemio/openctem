// Icon-only buttons are squares at every size (web/docs/ui-style-contract.md,
// "Sizes"). Finds, and with --write fixes, a <Button> whose content is only an
// icon but has a text size (default, sm, lg), and a button that is icon-only
// below a breakpoint without iconOnlyBelow.
// usage: node scripts/icon-buttons.mjs [--write]   (from web/)
// src/components/ui/__tests__/icon-button-guard.test.ts runs findIconButtons().
// Icon-only: every child (ignoring whitespace) is an icon element (a component
// imported from lucide-react, or an <svg>), a `{cond ? <Icon/> : <Icon/>}` of
// icons, or a visually hidden label (<span className="sr-only">); with asChild,
// the same test applies to the single child element's children.
import { readFileSync, writeFileSync } from 'node:fs'
import { execSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

export function findIconButtons(web, { write = false } = {}) {
  const files = execSync("git ls-files 'src/*.tsx' 'console/src/*.tsx'", {
    cwd: web,
    encoding: 'utf8',
  })
    .split('\n')
    .filter((f) => f && !/__tests__|\.test\.tsx$|\/components\/ui\//.test(f))

  const ICON_SIZES = new Set(['icon', 'icon-sm', 'xs'])
  const MAP = { default: 'icon', sm: 'icon-sm', lg: 'icon' }
  let total = 0
  const report = []

  for (const f of files) {
    const src = readFileSync(path.join(web, f), 'utf8')
    if (!src.includes('<Button')) continue
    const sf = ts.createSourceFile(f, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
    const icons = new Set()
    for (const st of sf.statements) {
      if (
        ts.isImportDeclaration(st) &&
        st.moduleSpecifier.text === 'lucide-react' &&
        st.importClause?.namedBindings
      ) {
        for (const el of st.importClause.namedBindings.elements ?? []) icons.add(el.name.text)
      }
    }
    const tagName = (n) => (ts.isJsxElement(n) ? n.openingElement.tagName : n.tagName).getText(sf)
    const attrs = (n) => (ts.isJsxElement(n) ? n.openingElement.attributes : n.attributes)
    const isIcon = (n) => {
      if (ts.isJsxSelfClosingElement(n) || ts.isJsxElement(n)) {
        const t = tagName(n)
        return (
          icons.has(t) || t === 'svg' || (/Icon$/.test(t) && icons.size > 0 && /^[A-Z]/.test(t))
        )
      }
      if (ts.isJsxExpression(n) && n.expression) {
        const e = n.expression
        if (ts.isConditionalExpression(e)) return isIconExpr(e.whenTrue) && isIconExpr(e.whenFalse)
        if (ts.isParenthesizedExpression(e)) return isIconExpr(e.expression)
        return false
      }
      return false
    }
    const isIconExpr = (e) => {
      while (ts.isParenthesizedExpression(e)) e = e.expression
      return (ts.isJsxSelfClosingElement(e) || ts.isJsxElement(e)) && isIcon(e)
    }
    const cls = (n) => {
      const a = n.openingElement.attributes.properties.find(
        (p) => ts.isJsxAttribute(p) && p.name.getText(sf) === 'className'
      )
      return a?.initializer?.getText(sf) ?? ''
    }
    // A label hidden at every width.
    const isSrOnly = (n) =>
      ts.isJsxElement(n) &&
      tagName(n) === 'span' &&
      /\bsr-only\b/.test(cls(n)) &&
      !/:not-sr-only/.test(cls(n))
    // A label shown only from a breakpoint up: the button is icon-only below it.
    const shownFrom = (n) => {
      if (!ts.isJsxElement(n) || tagName(n) !== 'span') return null
      const c = cls(n)
      let m = /\b(sm|md|lg):not-sr-only\b/.exec(c)
      if (m && /\bsr-only\b/.test(c)) return m[1]
      m =
        /(?:^|[\s"'`])hidden\b[^"'`]*\b(sm|md|lg):(inline|block|inline-flex|flex|inline-block)\b/.exec(
          c
        )
      return m ? m[1] : null
    }
    const meaningful = (kids) =>
      kids.filter(
        (k) =>
          !(ts.isJsxText(k) && k.text.trim() === '') && !(ts.isJsxExpression(k) && !k.expression)
      )
    // 'always' | 'sm' | 'md' | 'lg' (icon-only below that width) | null
    const iconOnly = (kids) => {
      const m = meaningful(kids)
      if (!(m.length > 0 && m.some(isIcon))) return null
      let below = null
      for (const k of m) {
        if (isIcon(k) || isSrOnly(k)) continue
        const bp = shownFrom(k)
        if (!bp) return null
        below = bp
      }
      return below ?? 'always'
    }
    const edits = []
    const visit = (n) => {
      if (ts.isJsxElement(n) && tagName(n) === 'Button') {
        const props = n.openingElement.attributes.properties
        const asChild = props.some((p) => ts.isJsxAttribute(p) && p.name.getText(sf) === 'asChild')
        let kids = n.children
        if (asChild) {
          const m = meaningful(kids)
          kids = m.length === 1 && ts.isJsxElement(m[0]) ? m[0].children : []
        }
        const kind = iconOnly(kids)
        const below = props.find(
          (p) => ts.isJsxAttribute(p) && p.name.getText(sf) === 'iconOnlyBelow'
        )
        if (kind && kind !== 'always' && !below) {
          const line = sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1
          report.push(`${f}:${line} icon-only below ${kind}`)
          const tn = n.openingElement.tagName
          edits.push([tn.getEnd(), tn.getEnd(), ` iconOnlyBelow="${kind}"`])
        }
        if (kind === 'always') {
          const sizeAttr = props.find((p) => ts.isJsxAttribute(p) && p.name.getText(sf) === 'size')
          const spread = props.some((p) => ts.isJsxSpreadAttribute(p))
          const val =
            sizeAttr?.initializer && ts.isStringLiteral(sizeAttr.initializer)
              ? sizeAttr.initializer.text
              : sizeAttr
                ? '?'
                : 'default'
          if (!ICON_SIZES.has(val)) {
            const line = sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1
            report.push(`${f}:${line} size=${val}${spread ? ' (spread)' : ''}`)
            if (val in MAP) {
              if (sizeAttr)
                edits.push([
                  sizeAttr.initializer.getStart(sf),
                  sizeAttr.initializer.getEnd(),
                  `"${MAP[val]}"`,
                ])
              else {
                const tn = n.openingElement.tagName
                edits.push([tn.getEnd(), tn.getEnd(), ` size="icon"`])
              }
            }
          }
        }
      }
      ts.forEachChild(n, visit)
    }
    visit(sf)
    if (edits.length && write) {
      let out = src
      for (const [s, e, t] of edits.sort((a, b) => b[0] - a[0]))
        out = out.slice(0, s) + t + out.slice(e)
      writeFileSync(path.join(web, f), out)
    }
    total += edits.length
  }
  return { report, fixed: write ? total : 0 }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
  const { report } = findIconButtons(web, { write: process.argv.includes('--write') })
  console.log(report.join('\n'))
  console.log(`icon-only buttons without a square size: ${report.length}`)
  process.exitCode = report.length && !process.argv.includes('--write') ? 1 : 0
}
