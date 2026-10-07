/**
 * Guard: no hand-written severity or criticality list.
 *
 * Severity (critical/high/medium/low/info) and asset criticality (critical/
 * high/medium/low/none) each have ONE source: `@/lib/severity` and
 * `@/lib/criticality`. Hand-written copies are how informational findings and
 * "Not rated" assets kept disappearing from filters, summaries and mappings:
 * someone wrote `['critical', 'high', 'medium', 'low']` and info was gone.
 *
 * The test parses every .ts/.tsx file under src/ and fails on:
 *  - an array literal of strings that contains critical, high, medium and low
 *    (this includes `z.enum([...])` and `as const` lists), and
 *  - four or more JSX `<SelectItem value="…">` siblings spelling out the same
 *    scale.
 *
 * Use SEVERITY_LEVELS / ACTIONABLE_SEVERITIES or ASSET_CRITICALITY_LEVELS /
 * RATED_CRITICALITY_LEVELS instead. A list that is NOT one of these scales
 * (a campaign priority, a license risk, a scan tool's threshold) goes in
 * NOT_A_SCALE with the reason.
 */
import fs from 'node:fs'
import path from 'node:path'

import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const SRC_ROOT = path.resolve(__dirname, '../..')

/** The shared sources themselves. */
const SOURCES = new Set(['lib/severity.ts', 'lib/criticality.ts'])

/**
 * Lists that look like the scale but are a different concept, keyed
 * `file|value,value,…`. Each needs the reason it is not finding severity or
 * asset criticality.
 */
const NOT_A_SCALE = new Map<string, string>([
  [
    'features/compliance/schemas/compliance.schema.ts|critical,high,medium,low',
    'compliance control priority (pkg/domain/compliance Priority), no info level',
  ],
  [
    'features/remediation-groups/components/create-campaign-from-group-dialog.tsx|critical,high,medium,low',
    'remediation campaign priority (pkg/domain/remediation CampaignPriority)',
  ],
  [
    'app/(dashboard)/(discovery)/components/page.tsx|critical,high,medium,low,unknown',
    'component license risk (chk_license_risk), not severity',
  ],
  [
    'app/(dashboard)/(validation)/control-testing/page.tsx|critical,high,medium,low',
    'control-test risk level of a compensating control, not finding severity',
  ],
  [
    'features/ci-runners/lib/ci.ts|critical,high,medium,low,none',
    'CI gate fail_on_severity threshold: none = never fail (chk_ci_gate_policies_severity)',
  ],
  [
    'features/notifications/lib/notification-filters.ts|critical,high,medium,low,info,none',
    'notification severity accepts none = system notices (chk_notification_outbox_severity)',
  ],
  [
    'features/attack-surface/components/easm-overview.tsx|critical,high,medium,low,info,none',
    'EASM exposure severity includes none (chk_exposures_severity); typed by ExposureSeverity',
  ],
  [
    'features/scan-profiles/schemas/scan-profile-schema.ts|info,low,medium,high,critical',
    'a scan tool minimum-severity threshold (the tool flag), least severe first by design',
  ],
  [
    'app/(dashboard)/settings/audit-log/page.tsx|info,low,medium,high,critical',
    'audit event severity (audit_logs.severity), a separate scale from finding severity',
  ],
  [
    'app/(dashboard)/(scoping)/compliance/page.tsx|critical,high,medium,low',
    'compliance control priority select (pkg/domain/compliance Priority)',
  ],
])

const SCALE = ['critical', 'high', 'medium', 'low']

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '__tests__' || entry.name === 'generated')
        continue
      out.push(...sourceFiles(full))
    } else if (/\.(ts|tsx)$/.test(entry.name) && !/\.(test|spec)\.tsx?$/.test(entry.name)) {
      out.push(full)
    }
  }
  return out
}

function isScale(values: string[]): boolean {
  return SCALE.every((v) => values.includes(v))
}

function stringElements(node: ts.ArrayLiteralExpression): string[] | null {
  const values: string[] = []
  for (const el of node.elements) {
    if (ts.isStringLiteral(el) || ts.isNoSubstitutionTemplateLiteral(el)) values.push(el.text)
    else return null
  }
  return values
}

function selectItemValue(node: ts.Node): string | null {
  const el = ts.isJsxSelfClosingElement(node)
    ? node
    : ts.isJsxElement(node)
      ? node.openingElement
      : null
  if (!el || el.tagName.getText() !== 'SelectItem') return null
  for (const attr of el.attributes.properties) {
    if (
      ts.isJsxAttribute(attr) &&
      attr.name.getText() === 'value' &&
      attr.initializer &&
      ts.isStringLiteral(attr.initializer)
    ) {
      return attr.initializer.text
    }
  }
  return null
}

interface ScaleHit {
  /** `file|value,value,…`, the NOT_A_SCALE key. */
  key: string
  /** `file:line [values]`, for the failure message. */
  where: string
}

function scanFile(file: string): ScaleHit[] {
  const rel = path.relative(SRC_ROOT, file).split(path.sep).join('/')
  if (SOURCES.has(rel)) return []
  const text = fs.readFileSync(file, 'utf8')
  if (!/['"]critical['"]/.test(text)) return []
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const hits: ScaleHit[] = []

  const report = (values: string[], node: ts.Node) => {
    const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf))
    hits.push({
      key: `${rel}|${values.join(',')}`,
      where: `${rel}:${line + 1} [${values.join(', ')}]`,
    })
  }

  const visit = (node: ts.Node) => {
    if (ts.isArrayLiteralExpression(node)) {
      const values = stringElements(node)
      if (values && isScale(values)) report(values, node)
    }
    if (ts.isJsxElement(node)) {
      // Sibling <SelectItem value="…"> children spelling out the scale.
      const values = node.children.map(selectItemValue).filter((v): v is string => v !== null)
      if (isScale(values)) report(values, node)
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return hits
}

/** Hand-written lists that are not allowlisted. */
function findHandWrittenScales(file: string): string[] {
  return scanFile(file)
    .filter((h) => !NOT_A_SCALE.has(h.key))
    .map((h) => h.where)
}

describe('severity / criticality scale guard', () => {
  it('has no hand-written severity or criticality list outside the shared sources', () => {
    const hits = sourceFiles(SRC_ROOT).flatMap(findHandWrittenScales)
    expect(
      hits,
      'Use SEVERITY_LEVELS (@/lib/severity) or ASSET_/RATED_CRITICALITY_LEVELS (@/lib/criticality); ' +
        'a list that is a different concept goes in NOT_A_SCALE with its reason.'
    ).toEqual([])
  })

  it('lists every NOT_A_SCALE entry against a file that still has it', () => {
    const present = new Set(sourceFiles(SRC_ROOT).flatMap((f) => scanFile(f).map((h) => h.key)))
    expect([...NOT_A_SCALE.keys()].filter((k) => !present.has(k))).toEqual([])
  })

  it('catches a hand-written list (self-test)', () => {
    const tmp = path.join(SRC_ROOT, 'lib', '__scale_guard_probe__.tsx')
    fs.writeFileSync(
      tmp,
      "export const A = ['critical', 'high', 'medium', 'low']\n" +
        'export const B = (\n  <Select>\n    <SelectItem value="critical">C</SelectItem>\n' +
        '    <SelectItem value="high">H</SelectItem>\n    <SelectItem value="medium">M</SelectItem>\n' +
        '    <SelectItem value="low">L</SelectItem>\n  </Select>\n)\n'
    )
    try {
      expect(findHandWrittenScales(tmp)).toHaveLength(2)
    } finally {
      fs.unlinkSync(tmp)
    }
  })
})
