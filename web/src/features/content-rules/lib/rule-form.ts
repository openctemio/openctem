/**
 * The editor's form state and its conversion to and from a detection rule
 * (api docs/architecture/rule-packs.md). The API validates every rule; these
 * helpers only shape what the form holds.
 */

import { SEVERITY_LEVELS } from '@/lib/severity'

import type { DetectionRule, MatcherLocation, RuleKind, RuleMatcher } from '../types'

export interface MatcherForm {
  location: MatcherLocation
  header: string
  /** Comma or newline separated. */
  keywords: string
  pattern: string
  /** Comma or newline separated. */
  hashes: string
}

export interface RuleForm {
  kind: RuleKind
  id: string
  name: string
  description: string
  condition: 'any' | 'all'
  techName: string
  techCategory: string
  techCpe: string
  confidence: string
  secretCategory: string
  secretSeverity: string
  matchers: MatcherForm[]
}

export const FINGERPRINT_LOCATIONS: MatcherLocation[] = [
  'header',
  'title',
  'cookie',
  'favicon',
  'script',
  'body',
  'url',
]
export const SECRET_LOCATIONS: MatcherLocation[] = ['body', 'script', 'url', 'title', 'header']
export const TECH_CATEGORIES = [
  'web_server',
  'framework',
  'language',
  'js_library',
  'cdn',
  'hosting',
  'waf',
  'analytics',
  'other',
]
export const SECRET_CATEGORIES = [
  'credential',
  'token',
  'private_key',
  'internal_host',
  'pii',
  'debug',
]
export const SEVERITIES: readonly string[] = SEVERITY_LEVELS

export function emptyMatcher(kind: RuleKind): MatcherForm {
  return {
    location: kind === 'secret-rules' ? 'body' : 'header',
    header: kind === 'secret-rules' ? '' : 'server',
    keywords: '',
    pattern: '',
    hashes: '',
  }
}

export function emptyForm(kind: RuleKind = 'web-fingerprints'): RuleForm {
  return {
    kind,
    id: '',
    name: '',
    description: '',
    condition: 'any',
    techName: '',
    techCategory: '',
    techCpe: '',
    confidence: '',
    secretCategory: 'token',
    secretSeverity: 'high',
    matchers: [emptyMatcher(kind)],
  }
}

/** Splits a comma or newline separated list, trimming and dropping blanks. */
export function splitList(s: string): string[] {
  return s
    .split(/[,\n]/)
    .map((x) => x.trim())
    .filter((x) => x !== '')
}

function matcherOf(m: MatcherForm): RuleMatcher {
  const out: RuleMatcher = { location: m.location }
  if (m.location === 'favicon') {
    out.hashes = splitList(m.hashes)
    return out
  }
  if (m.location === 'header') out.header = m.header.trim().toLowerCase()
  const keywords = splitList(m.keywords)
  if (keywords.length > 0) out.keywords = keywords
  if (m.pattern.trim() !== '') out.pattern = m.pattern
  return out
}

/** The rule the form describes, as the API takes it. */
export function toRule(f: RuleForm): DetectionRule {
  const rule: DetectionRule = {
    id: f.id.trim(),
    name: f.name.trim(),
    matchers: f.matchers.map(matcherOf),
  }
  if (f.description.trim() !== '') rule.description = f.description.trim()
  if (f.kind === 'web-fingerprints') {
    if (f.condition === 'all') rule.condition = 'all'
    rule.technology = { name: f.techName.trim() }
    if (f.techCategory) rule.technology.category = f.techCategory
    if (f.techCpe.trim() !== '') rule.technology.cpe = f.techCpe.trim()
    const c = Number.parseInt(f.confidence, 10)
    if (Number.isFinite(c) && c > 0) rule.confidence = c
  } else {
    rule.secret = { category: f.secretCategory, severity: f.secretSeverity }
  }
  return rule
}

/** The form of a stored rule. */
export function fromRule(kind: RuleKind, r: DetectionRule): RuleForm {
  return {
    kind,
    id: r.id,
    name: r.name,
    description: r.description ?? '',
    condition: r.condition === 'all' ? 'all' : 'any',
    techName: r.technology?.name ?? '',
    techCategory: r.technology?.category ?? '',
    techCpe: r.technology?.cpe ?? '',
    confidence: r.confidence ? String(r.confidence) : '',
    secretCategory: r.secret?.category ?? 'token',
    secretSeverity: r.secret?.severity ?? 'high',
    matchers: r.matchers.map((m) => ({
      location: m.location,
      header: m.header ?? '',
      keywords: (m.keywords ?? []).join(', '),
      pattern: m.pattern ?? '',
      hashes: (m.hashes ?? []).join(', '),
    })),
  }
}

/** Parses "name: value" lines into lower-case header names. */
export function parseHeaders(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of text.split('\n')) {
    const i = line.indexOf(':')
    if (i <= 0) continue
    const name = line.slice(0, i).trim().toLowerCase()
    if (name) out[name] = line.slice(i + 1).trim()
  }
  return out
}
