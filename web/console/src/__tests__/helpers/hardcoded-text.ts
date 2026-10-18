import ts from 'typescript'

/**
 * Finds user-visible text written straight into the console's components:
 * JSX text, string literals in user-visible props (placeholder, title,
 * aria-label, label, description, ...), string branches of `{cond ? 'a' : 'b'}`
 * children and toast messages. Everything a person reads goes through
 * t('key', 'English') with en and vi values; see the guard test.
 */

const TEXT_PROPS = new Set([
  'placeholder',
  'title',
  'aria-label',
  'aria-description',
  'label',
  'description',
  'alt',
  'emptyMessage',
  'confirmLabel',
  'cancelLabel',
  'tooltip',
  'helperText',
  'hint',
  'heading',
  'subtitle',
  'summary',
  'actionLabel',
  'submitLabel',
])

// Object properties that hold display text (table headers, option labels, ...).
const TEXT_KEYS = new Set([
  'header',
  'label',
  'title',
  'description',
  'placeholder',
  'emptyMessage',
  'confirmLabel',
  'message',
  'text',
  'tooltip',
  'hint',
])

const TOAST_METHODS = new Set(['success', 'error', 'info', 'warning', 'message', 'loading'])

/**
 * Words that are product, protocol or data-format names and read the same in
 * every language. A string made only of these (and punctuation, digits) is not
 * hard-coded prose.
 */
const NEUTRAL_WORDS = new Set(
  [
    'OpenCTEM',
    'SAML',
    'OIDC',
    'OAuth',
    'OpenID',
    'SCIM',
    'TOTP',
    'MFA',
    'SSO',
    'CIDR',
    'IP',
    'IPv4',
    'IPv6',
    'URL',
    'URI',
    'PEM',
    'JSON',
    'CSV',
    'API',
    'HTTP',
    'HTTPS',
    'DNS',
    'TLS',
    'SMTP',
    'Entra',
    'Okta',
    'Google',
    'Microsoft',
    'GitHub',
    'GitLab',
    'Turnstile',
    'ID',
    'UUID',
    'PKCE',
    'JWT',
    'SHA',
    'SSH',
    'ISO',
    'UTC',
    'MCP',
    'AI',
    'x',
    'gRPC',
    'mTLS',
  ].map((w) => w.toLowerCase())
)

/** True when the string is something a person would read as a sentence or label. */
export function isProse(raw: string): boolean {
  const text = raw.replace(/&[a-z]+;|&#\d+;/gi, ' ').trim()
  if (!/\p{L}{2,}/u.test(text)) return false
  // Environment variable names, identifiers, paths, URLs, CSS-like tokens.
  if (/^[A-Z][A-Z0-9_]+$/.test(text)) return false
  if (/^[\w.:/#@%-]+$/.test(text) && /[._:/#@%0-9]/.test(text)) return false
  if (/^[xX-]+$/.test(text)) return false
  if (/^\w+:\/\//.test(text) || text.startsWith('/') || text.startsWith('-----BEGIN')) return false
  const words = text.split(/[^\p{L}\p{N}]+/u).filter(Boolean)
  const real = words.filter((w) => /\p{L}{2,}/u.test(w) && !NEUTRAL_WORDS.has(w.toLowerCase()))
  return real.length > 0
}

export interface Hit {
  file: string
  line: number
  text: string
  node: ts.Node
  sf: ts.SourceFile
}

export function findHardcodedText(source: string, file: string): Hit[] {
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const hits: Hit[] = []
  const add = (node: ts.Node, text: string) => {
    if (!isProse(text)) return
    const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf))
    hits.push({ file, line: line + 1, text: text.trim().slice(0, 80), node, sf })
  }

  const stringsOf = (e: ts.Expression): Array<[ts.Node, string]> => {
    if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) return [[e, e.text]]
    if (ts.isTemplateExpression(e))
      return [[e, e.head.text + e.templateSpans.map((s) => ' ' + s.literal.text).join('')]]
    if (ts.isParenthesizedExpression(e)) return stringsOf(e.expression)
    if (ts.isConditionalExpression(e)) return [...stringsOf(e.whenTrue), ...stringsOf(e.whenFalse)]
    if (ts.isBinaryExpression(e)) {
      const op = e.operatorToken.kind
      if (
        op === ts.SyntaxKind.AmpersandAmpersandToken ||
        op === ts.SyntaxKind.BarBarToken ||
        op === ts.SyntaxKind.QuestionQuestionToken
      )
        return [...stringsOf(e.left), ...stringsOf(e.right)].filter(
          ([n]) => n !== e.left || op !== ts.SyntaxKind.AmpersandAmpersandToken
        )
    }
    return []
  }

  const visit = (node: ts.Node) => {
    if (ts.isJsxText(node)) {
      add(node, node.text)
    } else if (ts.isJsxAttribute(node) && TEXT_PROPS.has(node.name.getText(sf))) {
      const init = node.initializer
      if (init && ts.isStringLiteral(init)) add(init, init.text)
      else if (init && ts.isJsxExpression(init) && init.expression)
        for (const [n, s] of stringsOf(init.expression)) add(n, s)
    } else if (ts.isJsxExpression(node) && node.expression && !ts.isJsxAttribute(node.parent)) {
      for (const [n, s] of stringsOf(node.expression)) add(n, s)
    } else if (
      ts.isPropertyAssignment(node) &&
      (TEXT_KEYS.has(node.name.getText(sf).replace(/^['"]|['"]$/g, '')) ||
        // A sentence-like value under any other key: a lookup table of labels.
        ((ts.isStringLiteral(node.initializer) ||
          ts.isNoSubstitutionTemplateLiteral(node.initializer)) &&
          /^[A-Z][a-z]+(\s+\S+)+/.test(node.initializer.text) &&
          !/className|class|variant/i.test(node.name.getText(sf))))
    ) {
      for (const [n, s] of stringsOf(node.initializer)) add(n, s)
    } else if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'getErrorMessage' &&
      node.arguments[1]
    ) {
      for (const [n, s] of stringsOf(node.arguments[1])) add(n, s)
    } else if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      /^[A-Z][A-Z0-9_]*(MESSAGE|LABEL|TEXT|TITLE|HINT)$/.test(node.name.getText(sf)) &&
      (ts.isStringLiteral(node.initializer) || ts.isNoSubstitutionTemplateLiteral(node.initializer))
    ) {
      add(node.initializer, node.initializer.text)
    } else if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.expression.getText(sf) === 'toast' &&
      TOAST_METHODS.has(node.expression.name.text) &&
      node.arguments[0]
    ) {
      for (const [n, s] of stringsOf(node.arguments[0])) add(n, s)
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return hits
}
