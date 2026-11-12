/**
 * A configuration (compliance) check result, read from the finding: the
 * structured compliance fields, the source's own fields (a Nessus audit's
 * cm:compliance-* members land in source_extra), the actual value (the
 * scanner output), and, when those are missing, the sections of the
 * scanner's description.
 *
 * Every value is producer-supplied text; the panel renders it as text.
 */

import type { ComplianceOutcome, ComplianceSubCheck, FindingDetail } from '../types'

export type { ComplianceOutcome, ComplianceSubCheck }

const OUTCOMES: ComplianceOutcome[] = ['PASSED', 'FAILED', 'WARNING', 'ERROR', 'SKIPPED']

export interface ComplianceReferenceGroup {
  /** The framework as the source names it ("800-53", "CSCv8", "NESA"). */
  framework: string
  /** A readable name of the framework where one is known. */
  label: string
  ids: string[]
}

export interface ComplianceCheck {
  outcome?: ComplianceOutcome
  benchmark?: string
  benchmarkVersion?: string
  profile?: string
  auditFile?: string
  /** The benchmark's control number ("5.3.2.2"), else the source's control id. */
  control?: string
  policyValue?: string
  actualValue?: string
  /** Text of the actual value before its first sub-check ("All of the following must pass"). */
  preamble?: string
  subChecks: ComplianceSubCheck[]
  references: ComplianceReferenceGroup[]
  /** Why the check could not run (an unreadable file), as the scanner said. */
  error?: string
  /** source_extra keys the panel shows, so the source fields list skips them. */
  shownExtraKeys: string[]
}

type CheckInput = Pick<
  FindingDetail,
  'findingType' | 'complianceDetails' | 'sourceData' | 'scannerOutput' | 'description' | 'title'
>

function extraOf(f: CheckInput): Map<string, string> {
  return new Map(
    (f.sourceData?.sourceExtra ?? []).map(([k, v]) => [k.toLowerCase(), String(v ?? '')])
  )
}

/** PASSED / FAILED / … from a source value or the CTIS result. */
export function complianceOutcome(raw?: string, result?: string): ComplianceOutcome | undefined {
  const up = (raw ?? '').trim().toUpperCase()
  if ((OUTCOMES as string[]).includes(up)) return up as ComplianceOutcome
  switch ((result ?? '').toLowerCase()) {
    case 'pass':
      return 'PASSED'
    case 'fail':
      return 'FAILED'
    case 'manual':
    case 'review':
      return 'WARNING'
    case 'not_applicable':
      return 'SKIPPED'
  }
  return undefined
}

// The labelled sections of a Nessus compliance description.
const SECTION_NAMES = [
  'Rationale',
  'Impact',
  'Solution',
  'See Also',
  'Reference',
  'Policy Value',
  'Actual Value',
  'Audit',
  'Remediation',
  'Default Value',
  'Additional Information',
  'Description',
]
const SECTION_RE =
  /^(Rationale|Impact|Solution|See Also|Reference|Policy Value|Actual Value|Audit|Remediation|Default Value|Additional Information|Description)\s*:\s*(.*)$/i
const HEADLINE_RE = /^\s*"(.+)"\s*:\s*\[(PASSED|FAILED|WARNING|ERROR|SKIPPED)\]\s*$/i

export interface DescriptionParts {
  /** The '"<check>" : [FAILED]' first line, when present. */
  headline?: { check: string; outcome: ComplianceOutcome }
  /** The text before the first labelled section. */
  body: string
  sections: { name: string; text: string }[]
}

/** Splits a compliance description into its labelled sections. */
export function splitComplianceDescription(text: string): DescriptionParts {
  const lines = (text ?? '').replace(/\r\n?/g, '\n').split('\n')
  const parts: DescriptionParts = { body: '', sections: [] }
  const firstReal = lines.findIndex((l) => l.trim() !== '')
  if (firstReal !== -1) {
    const m = HEADLINE_RE.exec(lines[firstReal])
    if (m) {
      parts.headline = { check: m[1], outcome: m[2].toUpperCase() as ComplianceOutcome }
      lines.splice(0, firstReal + 1)
    }
  }
  const body: string[] = []
  let current: { name: string; lines: string[] } | null = null
  for (const l of lines) {
    const m = SECTION_RE.exec(l)
    if (m) {
      if (current)
        parts.sections.push({ name: current.name, text: current.lines.join('\n').trim() })
      const name = SECTION_NAMES.find((n) => n.toLowerCase() === m[1].toLowerCase()) ?? m[1]
      current = { name, lines: m[2] ? [m[2]] : [] }
    } else if (current) {
      current.lines.push(l)
    } else {
      body.push(l)
    }
  }
  if (current) parts.sections.push({ name: current.name, text: current.lines.join('\n').trim() })
  parts.body = body.join('\n').trim()
  return parts
}

/**
 * The description to show next to the compliance panel: without the
 * headline and the sections the panel already shows (references, policy
 * value, actual value), so nothing reads twice.
 */
export function complianceDescriptionText(text: string, check: ComplianceCheck): string {
  const parts = splitComplianceDescription(text)
  if (!parts.headline && parts.sections.length === 0) return text
  const shown = new Set<string>()
  if (check.references.length) shown.add('Reference')
  if (check.policyValue) shown.add('Policy Value')
  if (check.actualValue) shown.add('Actual Value')
  const kept = parts.sections.filter((s) => !shown.has(s.name) && s.text)
  return [parts.body, ...kept.map((s) => `${s.name}:\n${s.text}`)].filter(Boolean).join('\n\n')
}

const FRAMEWORK_LABEL: Record<string, string> = {
  '800-53': 'NIST SP 800-53',
  '800-53r5': 'NIST SP 800-53 Rev. 5',
  '800-171': 'NIST SP 800-171',
  '800-171r3': 'NIST SP 800-171 Rev. 3',
  csf: 'NIST CSF',
  'csf2.0': 'NIST CSF 2.0',
  cscv6: 'CIS Controls v6',
  cscv7: 'CIS Controls v7',
  cscv8: 'CIS Controls v8',
  hipaa: 'HIPAA',
  'iso/iec-27001': 'ISO/IEC 27001',
  'iso-27001-2022': 'ISO/IEC 27001:2022',
  'itsg-33': 'ITSG-33',
  'pci-dssv3.2.1': 'PCI DSS 3.2.1',
  'pci-dssv4.0': 'PCI DSS 4.0',
  nesa: 'NESA',
  'cn-l3': 'CN-L3',
  gdpr: 'GDPR',
  soc2: 'SOC 2',
  stig: 'DISA STIG',
}

/** "800-53|AC-7,CSCv8|5.4,800-53|AC-6(2)" grouped by framework, in source order. */
export function parseComplianceReferences(raw?: string): ComplianceReferenceGroup[] {
  const groups = new Map<string, ComplianceReferenceGroup>()
  for (const item of (raw ?? '').split(/[,\n]/)) {
    const cut = item.indexOf('|')
    const framework = (cut === -1 ? item : item.slice(0, cut)).trim()
    const id = cut === -1 ? '' : item.slice(cut + 1).trim()
    if (!framework) continue
    const key = framework.toLowerCase()
    let g = groups.get(key)
    if (!g) {
      g = { framework, label: FRAMEWORK_LABEL[key] ?? framework, ids: [] }
      groups.set(key, g)
    }
    if (id && !g.ids.includes(id)) g.ids.push(id)
  }
  return [...groups.values()]
}

const SEPARATOR_RE = /^\s*-{3,}\s*$/
const SUBCHECK_RE = /^\s*(?:-{3,}\s*)?(PASSED|FAILED|WARNING|ERROR|SKIPPED)\s*-\s*(.*)$/i
const ORDER: Record<ComplianceOutcome, number> = {
  FAILED: 0,
  ERROR: 1,
  WARNING: 2,
  SKIPPED: 3,
  PASSED: 4,
}

/** Failed first, then error, warning, skipped, passed; source order within each. */
export function sortSubChecks(list: ComplianceSubCheck[]): ComplianceSubCheck[] {
  return list
    .map((sc, i) => ({ sc, i }))
    .sort((a, b) => (ORDER[a.sc.outcome] ?? 5) - (ORDER[b.sc.outcome] ?? 5) || a.i - b.i)
    .map((x) => x.sc)
}

function fileOf(name: string, body: string): string | undefined {
  const text = `${name}\n${body}`
  const m =
    /\b(?:file(?:name)?|path)\s*[:=]\s*['"]?([^\s'";,]+)/i.exec(text) ??
    /\bThe file ["']([^"']+)["']/i.exec(text) ??
    /(?:^|[\s'"(])(\/(?:[\w.@+-]+\/)*[\w.@+-]+)/.exec(text)
  return m?.[1]
}

function expectOf(body: string): string | undefined {
  const m =
    /^\s*(?:expect|regex|expected)\s*[:=]\s*(.+)$/im.exec(body) ??
    /\b(?:does not contain|did not match|must match|contains?)\s+["'](.+?)["']/i.exec(body)
  return m?.[1].trim()
}

/**
 * The sub-checks of an actual value written as
 * "----- PASSED - name" (or a "-----" line, then "FAILED - name"), failed
 * first; the text before the first one is the preamble. No sub-check
 * headers: an empty list (the value is shown as it is).
 */
export function parseComplianceSubChecks(text?: string): {
  preamble: string
  subChecks: ComplianceSubCheck[]
} {
  const lines = (text ?? '').replace(/\r\n?/g, '\n').split('\n')
  const pre: string[] = []
  const found: { outcome: ComplianceOutcome; name: string; body: string[] }[] = []
  for (const l of lines) {
    const m = SUBCHECK_RE.exec(l)
    if (m) {
      found.push({ outcome: m[1].toUpperCase() as ComplianceOutcome, name: m[2].trim(), body: [] })
      continue
    }
    if (SEPARATOR_RE.test(l)) continue
    if (found.length) found[found.length - 1].body.push(l)
    else pre.push(l)
  }
  const subChecks = sortSubChecks(
    found.map((s) => {
      const detail = s.body.join('\n').trim()
      return {
        outcome: s.outcome,
        name: s.name,
        file: fileOf(s.name, detail),
        expect: expectOf(detail),
        detail,
      }
    })
  )
  return { preamble: subChecks.length ? pre.join('\n').trim() : '', subChecks }
}

const STRUCTURED_RESULT: Record<string, ComplianceOutcome> = {
  pass: 'PASSED',
  fail: 'FAILED',
  review: 'WARNING',
  error: 'ERROR',
  not_applicable: 'SKIPPED',
}

/**
 * The importer's sub-checks (source_extra compliance-subchecks: a JSON array
 * of {result, title, detail}, the detail cut at a few hundred characters
 * with its lines joined by "; "). A sub-check of the same title in the full
 * actual value lends its untruncated detail. Undefined when absent or not
 * an array.
 */
export function structuredSubChecks(
  raw: string | undefined,
  parsed: ComplianceSubCheck[] = []
): ComplianceSubCheck[] | undefined {
  if (!raw) return undefined
  let list: unknown
  try {
    list = JSON.parse(raw)
  } catch {
    return undefined
  }
  if (!Array.isArray(list) || list.length === 0) return undefined
  const out: ComplianceSubCheck[] = []
  for (const item of list.slice(0, 64)) {
    if (!item || typeof item !== 'object') continue
    const r = item as Record<string, unknown>
    const name = typeof r.title === 'string' ? r.title : ''
    const outcome =
      STRUCTURED_RESULT[String(r.result ?? '').toLowerCase()] ??
      complianceOutcome(String(r.result ?? ''))
    if (!outcome) continue
    const full = parsed.find((p) => p.name === name)
    if (full) {
      out.push({ ...full, outcome })
      continue
    }
    const detail = (typeof r.detail === 'string' ? r.detail : '').split(/;\s+/).join('\n').trim()
    out.push({ outcome, name, file: fileOf('', detail), expect: expectOf(detail), detail })
  }
  return out.length ? sortSubChecks(out) : undefined
}

const MAPPING_LABEL: Record<string, string> = {
  nist_800_53: 'NIST SP 800-53',
  nist_csf: 'NIST CSF',
  nist: 'NIST',
  cis: 'CIS',
  pci_dss: 'PCI DSS',
  iso27001: 'ISO/IEC 27001',
  hipaa: 'HIPAA',
  soc2: 'SOC 2',
  gdpr: 'GDPR',
  fedramp: 'FedRAMP',
}

/**
 * The importer's cross-framework mappings (source_extra compliance-mappings:
 * one "framework|version|control" per line), grouped by framework and
 * version in source order.
 */
export function parseComplianceMappings(raw?: string): ComplianceReferenceGroup[] {
  const groups = new Map<string, ComplianceReferenceGroup>()
  for (const row of (raw ?? '').split('\n')) {
    // "framework|version|control"; the control may itself contain "|".
    const a = row.indexOf('|')
    const b = a === -1 ? -1 : row.indexOf('|', a + 1)
    const framework = (a === -1 ? row : row.slice(0, a)).trim()
    const version = a === -1 ? '' : (b === -1 ? row.slice(a + 1) : row.slice(a + 1, b)).trim()
    const id = b === -1 ? '' : row.slice(b + 1).trim()
    if (!framework) continue
    const key = `${framework}|${version}`.toLowerCase()
    let g = groups.get(key)
    if (!g) {
      const base = MAPPING_LABEL[framework.toLowerCase()] ?? framework.toUpperCase()
      // "cis" + "controls v8" reads "CIS Controls v8".
      const v = version.replace(/^controls\b/i, 'Controls')
      g = { framework: key, label: v ? `${base} ${v}` : base, ids: [] }
      groups.set(key, g)
    }
    if (id && !g.ids.includes(id)) g.ids.push(id)
  }
  return [...groups.values()]
}

const CONTROL_NUMBER_RE = /^\s*(\d+(?:\.\d+)+)\s/

/** The compliance check of a configuration finding, or undefined for any other finding. */
export function complianceCheckOf(f: CheckInput): ComplianceCheck | undefined {
  const c = f.complianceDetails
  if (f.findingType !== 'compliance' && !c) return undefined
  const extra = extraOf(f)
  const get = (k: string) => extra.get(k)?.trim() || undefined
  const desc = splitComplianceDescription(f.description ?? '')
  const section = (name: string) => desc.sections.find((s) => s.name === name)?.text || undefined

  const policyValue = get('compliance-policy-value') ?? section('Policy Value')
  const actualValue = f.scannerOutput?.text?.trim() || section('Actual Value')
  const mappings = parseComplianceMappings(get('compliance-mappings'))
  // The importer's structured sub-checks win; the text is parsed otherwise.
  const parsed = parseComplianceSubChecks(actualValue)
  const structured = structuredSubChecks(get('compliance-subchecks'), parsed.subChecks)
  const subChecks = structured ?? parsed.subChecks
  const preamble = parsed.preamble
  const checkName = c?.controlName || desc.headline?.check || f.title
  const number = CONTROL_NUMBER_RE.exec(checkName ?? '')?.[1]

  const shownExtraKeys = [
    'compliance-result',
    'compliance-benchmark-name',
    'compliance-benchmark-version',
    'compliance-benchmark-profile',
    'compliance-audit-file',
    'compliance-policy-value',
    'compliance-reference',
    'compliance-mappings',
    'compliance-subchecks',
    'compliance-subcheck-counts',
    'compliance-description-original',
    'compliance-error',
  ].filter((k) => extra.has(k))

  return {
    outcome: complianceOutcome(get('compliance-result'), c?.result) ?? desc.headline?.outcome,
    benchmark:
      get('compliance-benchmark-name') ?? (c?.framework ? c.framework.toUpperCase() : undefined),
    benchmarkVersion: get('compliance-benchmark-version') ?? c?.frameworkVersion,
    profile: get('compliance-benchmark-profile'),
    auditFile: get('compliance-audit-file'),
    control: number ?? c?.controlId,
    policyValue,
    actualValue,
    preamble: preamble || undefined,
    subChecks,
    references: mappings.length
      ? mappings
      : parseComplianceReferences(get('compliance-reference') ?? section('Reference')),
    error: get('compliance-error'),
    shownExtraKeys,
  }
}
