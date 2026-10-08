/**
 * Guard: no data-driven `href` / `src` reaches the DOM without output encoding.
 *
 * Scanner references, evidence URIs, asset URLs and notification targets are
 * attacker-influenced (RFC-040 §5.4). A raw `href={finding.ref}` turns a
 * `data:` or `javascript:` value into a clickable link. This test parses
 * every .tsx file and checks each `href={…}` / `src={…}` JSX attribute. An
 * expression passes when it is provably safe:
 *
 *  - a string literal, or a template literal with a fixed same-origin path
 *    or a fixed `https://`/`http://`/`mailto:` prefix;
 *  - a call to an encoder (`safeHref`, `safeImageSrc`, `safeInternalHref`,
 *    `sanitizeExternalUrl`) or to an in-app route builder that returns a
 *    fixed-prefix path;
 *  - the attribute sits on `<SafeExternalLink>`, which encodes it itself;
 *  - a conditional / `??` / `||` whose branches all pass.
 *
 * Anything else must be listed in REVIEWED below with the reason it is not
 * data-driven (navigation config, a prop passthrough whose callers pass
 * route builders, a build-time constant). New entries need a reviewer to
 * agree; the usual fix is `<SafeExternalLink>` or `safeHref()` instead.
 */
import fs from 'node:fs'
import path from 'node:path'

import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const SRC_ROOT = path.resolve(__dirname, '../..')

/** Functions whose return value is safe for href/src. */
const SAFE_CALLS = new Set([
  // Encoders (src/lib/safe-href.ts, src/lib/utils.ts)
  'safeHref',
  'safeImageSrc',
  'safeInternalHref',
  'sanitizeExternalUrl',
  // Route builders: each returns a fixed same-origin prefix, or a fixed
  // https://attack.mitre.org prefix, with the data only in the path/query.
  'assetDetailHref',
  // features/assets/components/service-cells/issues-chip.tsx: `/findings?…`
  // with the asset id and fixed statuses in the query.
  'assetFindingsHref',
  'campaignHref',
  'findingsHrefForSources',
  'mitreTechniqueUrl',
  'registerHref',
])

/** Components that encode their own href. */
const SAFE_TAGS = new Set(['SafeExternalLink'])

/**
 * Reviewed non-data hrefs, keyed `file|Tag|attr={expression}`. Each one is
 * navigation config, a build-time constant or a prop whose callers pass a
 * route builder or a constant.
 */
const REVIEWED = new Set([
  // LEGAL_DOCS paths are constants in src/lib/legal.ts (/terms, /privacy, ...).
  'features/legal/components/legal-document.tsx|Link|href={d.path}',
  // Navigation config (src/config/*) and settings/category tables in code.
  'app/(dashboard)/settings/page.tsx|LinkCard|href={item.url}',
  // integrationManageHref returns one of the constant settings paths only.
  'app/(dashboard)/settings/integrations/page.tsx|Link|href={integrationManageHref(row.original)}',
  'app/(dashboard)/settings/integrations/page.tsx|LinkCard|href={category.href}',
  'components/profile-dropdown.tsx|Link|href={item.url}',
  'components/layout/grouped-nav.tsx|SidebarLink|href={item.url}',
  'components/layout/nav-group.tsx|SidebarLink|href={item.url}',
  'components/layout/nav-group.tsx|SidebarLink|href={url}',
  'components/layout/top-nav.tsx|Link|href={href}',
  'components/layout/breadcrumb-nav.tsx|Link|href={item.path}',
  'components/layout/settings-sidebar-nav.tsx|SidebarLink|href={backHref}',
  'components/layout/sidebar-brand.tsx|Link|href={href}',
  'components/layout/module-gate.tsx|Link|href={backUrl}',
  'components/layout/org-card.tsx|Link|href={membersLink.url}',
  'components/layout/org-card.tsx|Link|href={apiKeysLink.url}',
  'features/shared/components/section-tabs.tsx|Link|href={tab.href}',
  // Inventory overview: same-origin /assets?... paths built by buildOverview
  // (serializeInventoryFilters) and the fixed per-lens hint routes.
  'features/assets/components/overview/asset-categories-view.tsx|Link|href={href}',
  'features/assets/components/overview/asset-categories-view.tsx|Link|href={lens.href}',
  'features/assets/components/overview/asset-categories-view.tsx|Link|href={hint.href}',
  'features/assets/components/overview/asset-categories-view.tsx|Link|href={t.href}',
  'features/assets/components/overview/asset-categories-view.tsx|AttentionChip|href={lens.unownedHref}',
  'features/assets/components/overview/asset-categories-view.tsx|AttentionChip|href={lens.highRiskHref}',
  'features/assets/components/overview/asset-categories-view.tsx|AttentionChip|href={lens.reviewHref}',
  'features/dashboard/components/ctem/ctem-loop.tsx|Link|href={stage.href}',
  'features/scoping/components/scoping-overview.tsx|Link|href={r.href}',
  'app/(dashboard)/(validation)/validation/page.tsx|Link|href={a.href}',
  // Build-time constants (process.env / literals in the module).
  'components/layout/about-dialog.tsx|a|href={DOCS_URL}',
  'components/layout/sidebar-footer-links.tsx|a|href={DOCS_URL}',
  'components/layout/sidebar-footer-links.tsx|a|href={REPORT_ISSUE_URL}',
  'features/auth/components/legal-notice.tsx|a|href={termsUrl}',
  'features/auth/components/legal-notice.tsx|a|href={privacyUrl}',
  // Same-origin paths built in the component from route builders/literals.
  'app/(dashboard)/(discovery)/components/page.tsx|Link|href={href}',
  'features/assets/components/linked-assets-panel.tsx|Link|href={viewAllHref}',
  'features/attack-surface/components/path-graph.tsx|Link|href={node.href}',
  'features/dashboard/components/ctem/fix-next-queue.tsx|Link|href={it.href}',
  'features/auth/components/password-token-form.tsx|Link|href={copy.newLink.href}',
  'features/dashboards/widgets/registry.tsx|Link|href={href}',
  // Prop passthroughs: every caller passes a literal or route builder.
  'features/shared/components/link-card.tsx|Link|href={href}',
  'features/dashboard/components/activity-item.tsx|Link|href={href}',
])

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '__tests__') continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(full, out)
    else if (entry.name.endsWith('.tsx') && !/\.(test|spec)\.tsx$/.test(entry.name)) out.push(full)
  }
  return out
}

function isSafeTemplateHead(text: string): boolean {
  if (text.startsWith('/')) return !text.startsWith('//') && !text.startsWith('/\\')
  return /^(?:https?:\/\/[^/$]+\/|mailto:|#|\?)/i.test(text)
}

function calleeName(expr: ts.LeftHandSideExpression): string | undefined {
  if (ts.isIdentifier(expr)) return expr.text
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text
  return undefined
}

/**
 * `const href = safeHref(x)` then `href={href}`: an identifier is safe when
 * its `const` declaration in the same file is. Filled per file by scan().
 */
let localConsts = new Map<string, ts.Expression>()

function collectConsts(sf: ts.SourceFile): Map<string, ts.Expression> {
  const consts = new Map<string, ts.Expression>()
  const visit = (node: ts.Node) => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      ts.isVariableDeclarationList(node.parent) &&
      node.parent.flags & ts.NodeFlags.Const
    ) {
      // A name declared twice in one file is ambiguous: treat it as unsafe.
      if (consts.has(node.name.text))
        consts.set(node.name.text, ts.factory.createIdentifier('$ambiguous'))
      else consts.set(node.name.text, node.initializer)
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return consts
}

function isSafeExpression(expr: ts.Expression, depth = 0): boolean {
  if (depth > 5) return false
  if (ts.isIdentifier(expr) && localConsts.has(expr.text))
    return isSafeExpression(localConsts.get(expr.text)!, depth + 1)
  if (ts.isParenthesizedExpression(expr)) return isSafeExpression(expr.expression, depth)
  if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) return true
  if (ts.isTemplateExpression(expr)) return isSafeTemplateHead(expr.head.text)
  if (ts.isIdentifier(expr) && expr.text === 'undefined') return true
  if (expr.kind === ts.SyntaxKind.NullKeyword) return true
  if (ts.isCallExpression(expr)) {
    const name = calleeName(expr.expression)
    return name !== undefined && SAFE_CALLS.has(name)
  }
  if (ts.isConditionalExpression(expr))
    return isSafeExpression(expr.whenTrue) && isSafeExpression(expr.whenFalse)
  if (
    ts.isBinaryExpression(expr) &&
    (expr.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken ||
      expr.operatorToken.kind === ts.SyntaxKind.BarBarToken)
  )
    return isSafeExpression(expr.left) && isSafeExpression(expr.right)
  if (ts.isNonNullExpression(expr)) return isSafeExpression(expr.expression)
  return false
}

interface Violation {
  key: string
  where: string
}

function scan(): Violation[] {
  const violations: Violation[] = []
  for (const file of walk(SRC_ROOT)) {
    const rel = path.relative(SRC_ROOT, file).split(path.sep).join('/')
    const text = fs.readFileSync(file, 'utf8')
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
    localConsts = collectConsts(sf)
    const visit = (node: ts.Node) => {
      if (
        ts.isJsxAttribute(node) &&
        ts.isIdentifier(node.name) &&
        (node.name.text === 'href' || node.name.text === 'src') &&
        node.initializer &&
        ts.isJsxExpression(node.initializer) &&
        node.initializer.expression
      ) {
        const element = node.parent.parent as ts.JsxOpeningLikeElement
        const tag = element.tagName.getText(sf)
        const expr = node.initializer.expression
        if (!SAFE_TAGS.has(tag) && !isSafeExpression(expr)) {
          const exprText = expr.getText(sf).replace(/\s+/g, ' ')
          const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf))
          violations.push({
            key: `${rel}|${tag}|${node.name.text}={${exprText}}`,
            where: `${rel}:${line + 1}`,
          })
        }
      }
      ts.forEachChild(node, visit)
    }
    visit(sf)
  }
  return violations
}

describe('raw href/src guard (RFC-040 output encoding)', () => {
  const violations = scan()

  it('every data-driven href/src goes through safeHref/safeImageSrc/<SafeExternalLink>', () => {
    const unreviewed = violations.filter((v) => !REVIEWED.has(v.key))
    expect(
      unreviewed.map((v) => `${v.where}  ${v.key}`),
      'Wrap the value in <SafeExternalLink>, safeHref() or safeImageSrc(). ' +
        'Only if it is provably not data-driven, add it to REVIEWED with a reason.'
    ).toEqual([])
  })

  it('has no stale REVIEWED entries', () => {
    const seen = new Set(violations.map((v) => v.key))
    expect([...REVIEWED].filter((k) => !seen.has(k))).toEqual([])
  })

  it('flags the shapes it is meant to catch', () => {
    const parse = (code: string) => {
      const sf = ts.createSourceFile('x.tsx', code, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
      let found: ts.Expression | undefined
      const visit = (n: ts.Node) => {
        if (ts.isJsxAttribute(n) && n.initializer && ts.isJsxExpression(n.initializer))
          found = n.initializer.expression
        ts.forEachChild(n, visit)
      }
      visit(sf)
      localConsts = collectConsts(sf)
      return found!
    }
    expect(isSafeExpression(parse('<a href={ref} />'))).toBe(false)
    expect(isSafeExpression(parse('<a href={finding.references[0]} />'))).toBe(false)
    expect(isSafeExpression(parse('<a href={`${base}/x`} />'))).toBe(false)
    expect(isSafeExpression(parse('<a href={`//${host}`} />'))).toBe(false)
    expect(isSafeExpression(parse('<a href={ok ? safeHref(u) : u} />'))).toBe(false)
    expect(isSafeExpression(parse('<a href={safeHref(u)} />'))).toBe(true)
    expect(isSafeExpression(parse('<a href={`/findings/${id}`} />'))).toBe(true)
    expect(isSafeExpression(parse('<a href={`https://nvd.nist.gov/vuln/${id}`} />'))).toBe(true)
    expect(isSafeExpression(parse('const h = safeHref(u); <a href={h} />'))).toBe(true)
    expect(isSafeExpression(parse('const h = u.url; <a href={h} />'))).toBe(false)
  })
})
