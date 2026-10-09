/**
 * Pure helpers of the program import form (RFC-065). The server validates
 * everything again; these only shape what the person typed and summarize
 * what the server answered.
 */

import type {
  ForbiddenTechnique,
  ProgramHeader,
  ProgramPreview,
  ProgramRules,
  ProgramStatus,
} from '../api/programs-api.types'

export const FORBIDDEN_TECHNIQUES: { value: ForbiddenTechnique; label: string }[] = [
  { value: 'automated_scanning', label: 'Automated scanning' },
  { value: 'dos', label: 'Denial of service' },
  { value: 'intrusive', label: 'Intrusive testing' },
  { value: 'bruteforce', label: 'Brute force' },
  { value: 'social_engineering', label: 'Social engineering' },
  { value: 'physical', label: 'Physical testing' },
]

export const PROGRAM_STATUS_LABEL: Record<ProgramStatus, string> = {
  active: 'Active',
  paused: 'Suspended',
  ended: 'Ended',
}

/**
 * Reads "Name: value" lines into headers. Blank lines are skipped; a line
 * without a colon or with an empty name is reported by its number.
 */
export function parseHeaderLines(text: string): { headers: ProgramHeader[]; invalid: number[] } {
  const headers: ProgramHeader[] = []
  const invalid: number[] = []
  text.split('\n').forEach((raw, i) => {
    const line = raw.trim()
    if (!line) return
    const at = line.indexOf(':')
    const name = at > 0 ? line.slice(0, at).trim() : ''
    if (!name || /\s/.test(name)) {
      invalid.push(i + 1)
      return
    }
    headers.push({ name, value: line.slice(at + 1).trim() })
  })
  return { headers, invalid }
}

export interface RulesForm {
  rateLimit: string
  headers: string
  userAgent: string
  forbidden: ForbiddenTechnique[]
  notes: string
}

/** The rules the form describes (the server bounds and validates them). */
export function rulesFromForm(f: RulesForm): ProgramRules {
  const rps = Number.parseInt(f.rateLimit, 10)
  return {
    rate_limit_rps: Number.isFinite(rps) && rps > 0 ? rps : 0,
    required_headers: parseHeaderLines(f.headers).headers,
    user_agent: f.userAgent.trim(),
    forbidden: [...f.forbidden].sort(),
    notes: f.notes.trim(),
  }
}

export interface PreviewSummary {
  create: number
  keep: number
  alreadyCovered: number
  refused: number
  exclusions: number
  overlaps: number
  notScannable: number
}

/** Counts of what an import would do. */
export function summarizePreview(p: ProgramPreview): PreviewSummary {
  const s: PreviewSummary = {
    create: 0,
    keep: 0,
    alreadyCovered: 0,
    refused: 0,
    exclusions: p.exclusions.length,
    overlaps: p.exclusions.filter((x) => x.in_scope_by).length,
    notScannable: p.not_scannable.length,
  }
  for (const e of p.entries) {
    if (e.status === 'create') s.create++
    else if (e.status === 'keep') s.keep++
    else if (e.status === 'already_covered') s.alreadyCovered++
    else s.refused++
  }
  return s
}

/** Short form of a terms hash for display. */
export function shortHash(h: string | undefined): string {
  return h ? `${h.slice(0, 12)}…` : ''
}
