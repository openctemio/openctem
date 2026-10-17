/**
 * Display helpers for the finding import (POST /api/v1/findings/import).
 * Every value comes from an uploaded file and is rendered as text.
 */

import type { ImportFileResponse } from '../api/finding-import-api'
import { SEVERITY_LEVELS } from '@/lib/severity'

const FORMAT_LABELS: Record<string, string> = {
  nessus: 'Nessus (.nessus)',
  qualys: 'Qualys detections',
  qualys_kb: 'Qualys KnowledgeBase',
  cyclonedx: 'CycloneDX',
  spdx: 'SPDX',
  osv: 'OSV scanner results',
  csaf: 'CSAF',
  openvex: 'OpenVEX',
  defectdojo: 'DefectDojo Generic Findings',
  sarif: 'SARIF 2.1.0',
  trivy: 'trivy',
  grype: 'grype',
  semgrep: 'semgrep',
  opengrep: 'opengrep',
  gitleaks: 'gitleaks',
  betterleaks: 'betterleaks',
  nuclei: 'nuclei',
  zap: 'ZAP',
  vuls: 'vuls',
}

/** Human name of a detected format; the raw value when it is not known here. */
export function formatLabel(format?: string): string {
  if (!format) return 'Unknown format'
  return FORMAT_LABELS[format] ?? format
}

export const SEVERITY_ORDER = SEVERITY_LEVELS

/** Severity counts in display order, zero counts left out. */
export function severityCounts(file: ImportFileResponse): { severity: string; count: number }[] {
  const by = file.stats?.by_severity ?? {}
  return SEVERITY_ORDER.filter((s) => (by[s] ?? 0) > 0).map((s) => ({
    severity: s,
    count: by[s] ?? 0,
  }))
}

/** "line 12, column 4: message" / "message" for an issue or a file error. */
export function placeText(p: { line?: number; column?: number; message?: string }): string {
  const msg = p.message ?? ''
  if (!p.line) return msg
  const where = p.column ? `line ${p.line}, column ${p.column}` : `line ${p.line}`
  return `${where}: ${msg}`
}

export interface ImportTotals {
  files: number
  failed: number
  findings: number
  assets: number
  components: number
  statements: number
  created: number
  updated: number
  skippedOutOfScope: number
  vexMatched: number
  vexRequested: number
  vexWouldClose: number
}

/** Sums of the files of one upload. */
export function importTotals(files: ImportFileResponse[]): ImportTotals {
  const t: ImportTotals = {
    files: files.length,
    failed: 0,
    findings: 0,
    assets: 0,
    components: 0,
    statements: 0,
    created: 0,
    updated: 0,
    skippedOutOfScope: 0,
    vexMatched: 0,
    vexRequested: 0,
    vexWouldClose: 0,
  }
  for (const f of files) {
    if (f.error) t.failed++
    t.findings += f.stats?.findings ?? 0
    t.assets += f.stats?.assets ?? 0
    t.components += f.stats?.components ?? 0
    t.statements += f.stats?.statements ?? 0
    t.created += f.ingest?.findings_created ?? 0
    t.updated += f.ingest?.findings_updated ?? 0
    t.skippedOutOfScope += f.ingest?.assets_skipped_out_of_scope ?? 0
    t.vexMatched += f.vex?.matched ?? 0
    t.vexRequested += f.vex?.requested ?? 0
    t.vexWouldClose += f.vex?.would_close ?? 0
  }
  return t
}

/** Explains what a VEX not_affected statement will do on import. */
export function vexModeText(
  t: (key: string, fallback: string) => string,
  mode: string | undefined,
  canRequest: boolean | undefined
): string {
  if (mode === 'enforce' && canRequest) {
    return t(
      'findings.importResults.vexModeEnforce',
      'not_affected statements request false positive approval for the matching open findings; the findings stay open until another person approves.'
    )
  }
  if (mode === 'enforce') {
    return t(
      'findings.importResults.vexModeEnforceNoApprove',
      'not_affected statements are stored on the matching findings; requesting false positive approval needs the approve permission.'
    )
  }
  if (mode === 'off') {
    return t(
      'findings.importResults.vexModeOff',
      'VEX statements are stored on the matching findings only.'
    )
  }
  return t(
    'findings.importResults.vexModeDryRun',
    'VEX statements are stored on the matching findings and counted; no false positive approval is requested (dry run mode).'
  )
}
