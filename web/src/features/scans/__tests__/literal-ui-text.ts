/**
 * Finds user-visible text written straight into the scans components instead
 * of going through `t()`: JSX text, text-bearing JSX attributes, string
 * literals shown through JSX expressions, and toast messages.
 * Used by no-literal-ui-text.test.ts.
 */
import ts from 'typescript'

const TEXT_ATTRIBUTES = new Set([
  'placeholder',
  'title',
  'aria-label',
  'aria-description',
  'aria-placeholder',
  'alt',
  'label',
  'description',
  'emptyMessage',
  'tooltip',
])

/** Object properties whose string value is shown to people (column headers, option labels...). */
const TEXT_PROPERTIES = new Set([
  'header',
  'label',
  'title',
  'description',
  'placeholder',
  'emptyMessage',
  'tooltip',
  'hint',
])

export interface LiteralFinding {
  line: number
  kind: 'jsx-text' | 'attribute' | 'expression' | 'toast' | 'property'
  text: string
}

/** Prose, not a code sample: has letters, and is not all host names / paths / patterns. */
const hasWords = (raw: string) => {
  const s = raw.replace(/&\w+;/g, ' ')
  return (
    /[\p{L}]{2,}/u.test(s) &&
    !s
      .trim()
      .split(/\s+/)
      .every((tok) => /[./:*@_\\]|^\d+$/.test(tok))
  )
}

export function findLiteralUiText(fileName: string, source: string): LiteralFinding[] {
  const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const out: LiteralFinding[] = []
  const add = (node: ts.Node, kind: LiteralFinding['kind'], text: string) => {
    const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf))
    out.push({ line: line + 1, kind, text: text.trim().slice(0, 80) })
  }
  // String literals that reach the screen through a JSX expression:
  // {cond ? 'a' : 'b'}, {'a'}, {x && 'a'}, {x ?? 'a'}, `template ${x}`.
  const visitShown = (node: ts.Node) => {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      if (hasWords(node.text)) add(node, 'expression', node.text)
    } else if (ts.isTemplateExpression(node)) {
      const text = [node.head.text, ...node.templateSpans.map((s) => s.literal.text)].join(' ')
      if (hasWords(text)) add(node, 'expression', text)
    } else if (ts.isConditionalExpression(node)) {
      visitShown(node.whenTrue)
      visitShown(node.whenFalse)
    } else if (ts.isBinaryExpression(node)) {
      visitShown(node.right)
      if (node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken) visitShown(node.left)
    } else if (ts.isParenthesizedExpression(node)) {
      visitShown(node.expression)
    }
  }
  const isToastCall = (node: ts.CallExpression) =>
    ts.isPropertyAccessExpression(node.expression) &&
    ts.isIdentifier(node.expression.expression) &&
    node.expression.expression.text === 'toast'
  const isInsideToast = (node: ts.Node) => {
    for (let n: ts.Node | undefined = node.parent; n; n = n.parent) {
      if (ts.isCallExpression(n) && isToastCall(n)) return true
    }
    return false
  }
  const visit = (node: ts.Node) => {
    if (ts.isJsxText(node)) {
      if (hasWords(node.text)) add(node, 'jsx-text', node.text)
    } else if (ts.isJsxAttribute(node) && node.initializer) {
      const name = node.name.getText(sf)
      if (TEXT_ATTRIBUTES.has(name)) {
        const init = node.initializer
        if (ts.isStringLiteral(init)) {
          if (hasWords(init.text)) add(init, 'attribute', `${name}="${init.text}"`)
        } else if (ts.isJsxExpression(init) && init.expression) {
          const before = out.length
          visitShown(init.expression)
          for (let i = before; i < out.length; i++) out[i].kind = 'attribute'
        }
      }
    } else if (
      ts.isPropertyAssignment(node) &&
      (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name)) &&
      TEXT_PROPERTIES.has(node.name.text) &&
      !isInsideToast(node)
    ) {
      const before = out.length
      visitShown(node.initializer)
      for (let i = before; i < out.length; i++) out[i].kind = 'property'
    } else if (ts.isJsxExpression(node) && node.expression && !ts.isJsxAttribute(node.parent)) {
      visitShown(node.expression)
    } else if (ts.isCallExpression(node) && isToastCall(node)) {
      const [message, opts] = node.arguments
      if (message) {
        const before = out.length
        visitShown(message)
        for (let i = before; i < out.length; i++) out[i].kind = 'toast'
      }
      if (opts && ts.isObjectLiteralExpression(opts)) {
        for (const p of opts.properties) {
          if (
            ts.isPropertyAssignment(p) &&
            ts.isIdentifier(p.name) &&
            (p.name.text === 'description' || p.name.text === 'label')
          ) {
            visitShown(p.initializer)
          }
          if (
            ts.isPropertyAssignment(p) &&
            ts.isIdentifier(p.name) &&
            p.name.text === 'action' &&
            ts.isObjectLiteralExpression(p.initializer)
          ) {
            for (const a of p.initializer.properties) {
              if (
                ts.isPropertyAssignment(a) &&
                ts.isIdentifier(a.name) &&
                a.name.text === 'label'
              ) {
                visitShown(a.initializer)
              }
            }
          }
        }
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return out
}
