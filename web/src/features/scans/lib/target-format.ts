/**
 * The format of a typed scan target: domain, wildcard, IP, CIDR, URL or
 * host:port. Format only: whether a target may be scanned (scope, zones,
 * private ranges, tiers) is the API's answer (POST /scope/check), never
 * decided here.
 */

export type TargetKind =
  'domain' | 'wildcard' | 'ipv4' | 'ipv6' | 'cidr' | 'url' | 'host:port' | 'invalid'

export interface ClassifiedTarget {
  /** The line as typed (trimmed). */
  input: string
  /** The form sent to the API (lower-case host, no trailing dot). */
  value: string
  kind: TargetKind
  /** Why an invalid line is invalid (English; the UI shows `reasonKey`). */
  reason?: string
  /** i18n key of the reason. */
  reasonKey?: string
}

export const TARGET_KIND_LABELS: Record<TargetKind, string> = {
  domain: 'Domain',
  wildcard: 'Wildcard',
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  cidr: 'CIDR',
  url: 'URL',
  'host:port': 'Host:port',
  invalid: 'Invalid',
}

const REASONS = {
  empty: 'Empty line',
  urlChars: 'Contains characters a URL cannot have',
  noHost: 'No host',
  badUrl: 'Not a valid URL',
  targetChars: 'Contains characters a target cannot have',
  wildcardForm: 'A wildcard is *. followed by a domain',
  badCidr: 'Not a valid CIDR range',
  badHostPort: 'Not a valid host:port',
  unknown: 'Not a domain, IP address, CIDR range, URL or host:port',
} as const

const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
const DOMAIN = new RegExp(`^(?:${LABEL}\\.)+[a-z]{2,63}$`)
const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
const IPV4 = new RegExp(`^${OCTET}(?:\\.${OCTET}){3}$`)
// Shell and markup characters never appear in a target.
const UNSAFE = /[;&|`$(){}<>\\'"!\s]/

function isIPv6(s: string): boolean {
  if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return false
  try {
    return new URL(`http://[${s}]/`).hostname.length > 2
  } catch {
    return false
  }
}

/** The format of one typed line. */
export function classifyTarget(raw: string): ClassifiedTarget {
  const input = raw.trim()
  const invalid = (id: keyof typeof REASONS): ClassifiedTarget => ({
    input,
    value: input,
    kind: 'invalid',
    reason: REASONS[id],
    reasonKey: `scans.targetReason.${id}`,
  })
  if (!input) return invalid('empty')

  if (/^https?:\/\//i.test(input)) {
    if (/[\s<>"'`\\]/.test(input)) return invalid('urlChars')
    try {
      const url = new URL(input)
      if (!url.hostname) return invalid('noHost')
      return { input, value: input, kind: 'url' }
    } catch {
      return invalid('badUrl')
    }
  }
  if (UNSAFE.test(input) || input.includes('[') || input.includes(']')) {
    return invalid('targetChars')
  }

  const lower = input.toLowerCase().replace(/\.$/, '')
  if (lower.startsWith('*.')) {
    return DOMAIN.test(lower.slice(2))
      ? { input, value: lower, kind: 'wildcard' }
      : invalid('wildcardForm')
  }
  if (IPV4.test(lower)) return { input, value: lower, kind: 'ipv4' }
  if (lower.includes('/')) {
    const [addr, bits, ...rest] = lower.split('/')
    const n = Number(bits)
    if (rest.length === 0 && /^\d{1,3}$/.test(bits ?? '')) {
      if (IPV4.test(addr) && n <= 32) return { input, value: lower, kind: 'cidr' }
      if (isIPv6(addr) && n <= 128) return { input, value: lower, kind: 'cidr' }
    }
    return invalid('badCidr')
  }
  if (isIPv6(lower)) return { input, value: lower, kind: 'ipv6' }
  const hp = /^(.+):(\d{1,5})$/.exec(lower)
  if (hp) {
    const port = Number(hp[2])
    const host = hp[1]
    if (
      port >= 1 &&
      port <= 65535 &&
      (DOMAIN.test(host) || IPV4.test(host) || host === 'localhost')
    ) {
      return { input, value: lower, kind: 'host:port' }
    }
    return invalid('badHostPort')
  }
  if (DOMAIN.test(lower)) return { input, value: lower, kind: 'domain' }
  return invalid('unknown')
}

export interface PastedTargets {
  /** Every non-empty line, classified, in order. */
  lines: ClassifiedTarget[]
  /** Valid targets, normalized, without repeats. */
  targets: string[]
  invalid: ClassifiedTarget[]
  /** Lines that repeat an earlier target. */
  duplicates: number
  byKind: Partial<Record<TargetKind, number>>
}

/** Classify, normalize and de-duplicate typed lines. */
export function parsePastedTargets(lines: string[]): PastedTargets {
  const out: PastedTargets = { lines: [], targets: [], invalid: [], duplicates: 0, byKind: {} }
  const seen = new Set<string>()
  // A target never holds a comma, a semicolon or a space: a pasted list may
  // use any of them between targets.
  const tokens = lines.flatMap((line) => line.split(/[,;\s]+/))
  for (const raw of tokens) {
    if (!raw.trim()) continue
    const c = classifyTarget(raw)
    out.lines.push(c)
    out.byKind[c.kind] = (out.byKind[c.kind] ?? 0) + 1
    if (c.kind === 'invalid') {
      out.invalid.push(c)
      continue
    }
    const key = c.value.toLowerCase()
    if (seen.has(key)) {
      out.duplicates++
      continue
    }
    seen.add(key)
    out.targets.push(c.value)
  }
  return out
}
