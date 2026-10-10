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
  ScopeFileFormat,
  ScopeFileInput,
  TestingWindow,
  WeekDay,
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

export const WEEK_DAYS: WeekDay[] = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']

const WINDOW_TIME = /^([01]\d|2[0-3]):[0-5]\d$/

/** Reads "mon,wed" or "mon-fri" (a range wraps: "sat-sun"). */
function parseDays(spec: string): WeekDay[] | null {
  const out = new Set<WeekDay>()
  for (const part of spec.toLowerCase().split(',')) {
    const [a, b] = part.split('-').map((x) => x.trim()) as [WeekDay, WeekDay | undefined]
    const from = WEEK_DAYS.indexOf(a)
    if (from < 0) return null
    if (b === undefined) {
      out.add(a)
      continue
    }
    const to = WEEK_DAYS.indexOf(b)
    if (to < 0) return null
    for (let i = from; ; i = (i + 1) % 7) {
      out.add(WEEK_DAYS[i])
      if (i === to) break
    }
  }
  return WEEK_DAYS.filter((d) => out.has(d))
}

/**
 * Reads testing windows, one per line: "mon-fri 09:00-17:00 Europe/Paris".
 * Blank lines are skipped; a malformed line is reported by its number. The
 * server checks the time zone.
 */
export function parseWindowLines(text: string): { windows: TestingWindow[]; invalid: number[] } {
  const windows: TestingWindow[] = []
  const invalid: number[] = []
  text.split('\n').forEach((raw, i) => {
    const line = raw.trim()
    if (!line) return
    const [daySpec, span, timezone, ...rest] = line.split(/\s+/)
    const [start, end] = (span ?? '').split('-')
    const days = daySpec ? parseDays(daySpec) : null
    if (
      !days?.length ||
      !WINDOW_TIME.test(start ?? '') ||
      !WINDOW_TIME.test(end ?? '') ||
      end <= start ||
      !timezone ||
      rest.length
    ) {
      invalid.push(i + 1)
      return
    }
    windows.push({ days, start, end, timezone })
  })
  return { windows, invalid }
}

/** One window as the form writes it. */
export function formatWindow(w: TestingWindow): string {
  return `${w.days.join(',')} ${w.start}-${w.end} ${w.timezone}`
}

export interface RulesForm {
  rateLimit: string
  headers: string
  userAgent: string
  forbidden: ForbiddenTechnique[]
  notes: string
  windows?: string
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
    testing_windows: parseWindowLines(f.windows ?? '').windows,
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

/** The largest scope file the server reads (bytes). */
export const MAX_SCOPE_FILE_BYTES = 256 * 1024

export const SCOPE_FILE_FORMATS: { value: ScopeFileFormat; label: string }[] = [
  { value: 'auto', label: 'Detect from the file' },
  { value: 'platform_csv', label: 'Platform CSV export' },
  { value: 'burp_json', label: 'Burp Suite target scope (JSON)' },
  { value: 'generic_csv', label: 'Other CSV (choose the columns)' },
  { value: 'text', label: 'Plain list' },
]

/**
 * The column names of a CSV's header line (tab, semicolon or comma, as the
 * server reads it). Empty for an empty file.
 */
export function csvHeaderColumns(content: string): string[] {
  const first = content.replace(/^\uFEFF/, '').split(/\r?\n/, 1)[0] ?? ''
  if (!first.trim()) return []
  const sep = first.includes('\t')
    ? '\t'
    : (first.match(/;/g)?.length ?? 0) > (first.match(/,/g)?.length ?? 0)
      ? ';'
      : ','
  return first
    .split(sep)
    .map((c) => c.trim().replace(/^"(.*)"$/, '$1'))
    .filter((c) => c !== '')
}

/** Whether a file is too large to send (UTF-8 bytes, as the server counts). */
export function scopeFileTooLarge(content: string): boolean {
  return new TextEncoder().encode(content).length > MAX_SCOPE_FILE_BYTES
}

export interface ScopeFileForm {
  fileName: string
  fileContent: string
  fileFormat: ScopeFileFormat
  mapIdentifier: string
  mapType: string
  mapInScope: string
}

/** The scope_file of a request; the mapping only for a generic CSV. */
export function scopeFileFromForm(f: ScopeFileForm): ScopeFileInput {
  const out: ScopeFileInput = { format: f.fileFormat, name: f.fileName, content: f.fileContent }
  if (f.fileFormat === 'generic_csv') {
    out.mapping = { identifier: f.mapIdentifier }
    if (f.mapType) out.mapping.type = f.mapType
    if (f.mapInScope) out.mapping.in_scope = f.mapInScope
  }
  return out
}
