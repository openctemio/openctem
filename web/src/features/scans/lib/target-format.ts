/**
 * The format of a typed scan target: domain, wildcard, IP, CIDR, URL or
 * host:port. Format only: whether a target may be scanned (scope, zones,
 * private ranges, tiers) is the API's answer (POST /scope/check), never
 * decided here. The rules mirror the API's target validator
 * (api/pkg/validator/target.go) so that nothing accepted here is refused at
 * create: CIDRs of at most 2^24 addresses (an IPv4 /8, an IPv6 /104; the
 * organization may set a lower bound), `[v6]:port`, service names
 * (`host:25/tcp`), and paths or repositories refused as network targets.
 * Unicode domain names are sent in their ASCII (punycode) form.
 * The CIDR bounds and their words are one contract with the API:
 * api/pkg/validator/testdata/cidr_targets.json is read by both test suites.
 * Design: research/418; large ranges: api/docs/rfcs/RFC-151-large-range-targets.md.
 */

import type { Translate } from './translate'

export type TargetKind =
  'domain' | 'wildcard' | 'ipv4' | 'ipv6' | 'cidr' | 'url' | 'host:port' | 'repo' | 'invalid'

export interface ClassifiedTarget {
  /** The entry as typed (trimmed). */
  input: string
  /** The form sent to the API (lower-case host, no trailing dot, ASCII). */
  value: string
  kind: TargetKind
  /** Why an entry is not added (English; the UI shows `reasonKey`). */
  reason?: string
  /** i18n key of the reason. */
  reasonKey?: string
  /** Values the reason names (formatted numbers, the range). */
  reasonVars?: Record<string, string>
  /**
   * A range wider than one target can hold, that fits in at most
   * MAX_SPLIT_PIECES ranges of the widest accepted size: the prefix length
   * of those ranges and how many there are (splitCidr cuts it).
   */
  split?: { bits: number; count: number }
}

export const TARGET_KIND_LABELS: Record<TargetKind, string> = {
  domain: 'Domain',
  wildcard: 'Wildcard',
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  cidr: 'CIDR',
  url: 'URL',
  'host:port': 'Host:port',
  repo: 'Path or repository',
  invalid: 'Invalid',
}

/** Kinds that are never added as a typed target. */
export function isRefusedKind(kind: TargetKind): boolean {
  return kind === 'invalid' || kind === 'repo'
}

const REASONS = {
  empty: 'Empty line',
  urlChars: 'Contains characters a URL cannot have',
  noHost: 'No host',
  badUrl: 'Not a valid URL',
  targetChars: 'Contains characters a target cannot have',
  wildcardForm: 'A wildcard is *. followed by a domain',
  badCidr: 'Not a valid CIDR range',
  cidrTooLarge: '{cidr} has {count} addresses; the most one target can hold is {max} ({prefix})',
  badHostPort: 'Not a valid host:port',
  idnTld: 'A top-level domain in punycode (xn--) is not accepted yet',
  repo: 'Not a network target: a path or a repository. Add http:// or https:// for a web address; repositories are scanned from repository assets',
  unknown: 'Not a domain, IP address, CIDR range, URL or host:port',
} as const

const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
const DOMAIN = new RegExp(`^(?:${LABEL}\\.)+[a-z]{2,63}$`)
const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
const IPV4 = new RegExp(`^${OCTET}(?:\\.${OCTET}){3}$`)
// Shell and markup characters never appear in a target.
const UNSAFE = /[;&|`$(){}<>\\'"!\s]/
// Largest range the API takes: 2^24 addresses (an IPv4 /8, an IPv6 /104).
export const MAX_HOST_BITS = 24
/**
 * A range wider than this (2^16 addresses, an IPv4 /16) is a large range:
 * cut into /16 chunks at dispatch and scanned live hosts first.
 */
export const LARGE_RANGE_HOST_BITS = 16
/** The most ranges a too-large range is offered to be split into in one click. */
export const MAX_SPLIT_PIECES = 256

/** `{name}` placeholders of an English reason filled in. */
function fill(text: string, vars: Record<string, string>): string {
  return text.replace(/\{(\w+)\}/g, (m, k: string) => vars[k] ?? m)
}

/** A range wider than maxHostBits: the reason with its numbers, and the split it allows. */
function tooLarge(
  input: string,
  value: string,
  totalBits: number,
  prefix: number,
  maxHostBits: number
): ClassifiedTarget {
  const maxBits = totalBits - maxHostBits
  const reasonVars = {
    cidr: value,
    count: (BigInt(1) << BigInt(totalBits - prefix)).toLocaleString(),
    max: (2 ** maxHostBits).toLocaleString(),
    prefix: `/${maxBits}`,
  }
  const pieces = 2 ** (maxBits - prefix)
  return {
    input,
    value: input,
    kind: 'invalid',
    reason: fill(REASONS.cidrTooLarge, reasonVars),
    reasonKey: 'scans.targetReason.cidrTooLarge',
    reasonVars,
    ...(pieces <= MAX_SPLIT_PIECES ? { split: { bits: maxBits, count: pieces } } : {}),
  }
}

/** The address of a parsed IPv4 or IPv6 text as a number. */
function addrToBig(addr: string): bigint {
  if (IPV4.test(addr)) {
    return addr.split('.').reduce((acc, o) => (acc << BigInt(8)) | BigInt(Number(o)), BigInt(0))
  }
  // The browser's URL parser writes the canonical, fully expanded form.
  const host = new URL(`http://[${addr}]/`).hostname.slice(1, -1)
  const [head, tail = ''] = host.split('::')
  const h = head ? head.split(':') : []
  const tl = tail ? tail.split(':') : []
  const groups = host.includes('::')
    ? [...h, ...Array(8 - h.length - tl.length).fill('0'), ...tl]
    : h
  return groups.reduce((acc, g) => (acc << BigInt(16)) | BigInt(parseInt(g, 16)), BigInt(0))
}

function bigToV4(n: bigint): string {
  return [24, 16, 8, 0].map((sh) => Number((n >> BigInt(sh)) & BigInt(255))).join('.')
}

function bigToV6(n: bigint): string {
  const groups = [7, 6, 5, 4, 3, 2, 1, 0].map((i) =>
    ((n >> BigInt(i * 16)) & BigInt(0xffff)).toString(16)
  )
  // The canonical short form, through the browser's URL parser.
  return new URL(`http://[${groups.join(':')}]/`).hostname.slice(1, -1)
}

/**
 * A CIDR range cut into the ranges of prefix length `bits` that cover it
 * (`10.0.0.0/14`, 16 -> four /16 ranges). Host bits typed after the address
 * are ignored, as the API does. Empty when `cidr` is not a range, `bits` is
 * not narrower than its prefix, or there would be more than MAX_SPLIT_PIECES.
 */
export function splitCidr(cidr: string, bits: number): string[] {
  const [addr, len] = cidr.trim().toLowerCase().split('/')
  const prefix = Number(len)
  const v4 = IPV4.test(addr ?? '')
  if (!addr || !/^\d{1,3}$/.test(len ?? '') || (!v4 && !isIPv6(addr))) return []
  const total = v4 ? 32 : 128
  if (prefix > total || bits > total || bits <= prefix || bits - prefix > 8) return []
  const hostBits = BigInt(total - prefix)
  const base = (addrToBig(addr) >> hostBits) << hostBits
  const step = BigInt(1) << BigInt(total - bits)
  const out: string[] = []
  for (let i = 0; i < 2 ** (bits - prefix); i++) {
    const a = base + step * BigInt(i)
    out.push(`${v4 ? bigToV4(a) : bigToV6(a)}/${bits}`)
  }
  return out
}

function isIPv6(s: string): boolean {
  if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return false
  try {
    return new URL(`http://[${s}]/`).hostname.length > 2
  } catch {
    return false
  }
}

function validPort(p: string): boolean {
  const n = Number(p)
  return /^\d{1,5}$/.test(p) && n >= 1 && n <= 65535
}

/**
 * A Unicode domain in its ASCII form (`bücher.de` -> `xn--bcher-kva.de`),
 * through the browser's own IDNA mapping; ASCII input is returned lower-cased.
 */
function toAsciiHost(host: string): string | null {
  const lower = host.toLowerCase()
  if (/^[\x00-\x7f]*$/.test(lower)) return lower
  try {
    const ascii = new URL(`http://${lower}/`).hostname
    return ascii && !ascii.includes('%') ? ascii : null
  } catch {
    return null
  }
}

function punycodeTld(host: string): boolean {
  return /\.xn--[a-z0-9-]+$/.test(host)
}

/** A repository reference or a path: never a network target. */
function looksLikeRepo(input: string): boolean {
  if (/^git@[^\s:]+:\S+$/i.test(input)) return true
  if (/^(ssh|git|git\+ssh):\/\//i.test(input)) return true
  if (/^https?:\/\/\S+\.git\/?$/i.test(input)) return true
  return false
}

export interface ClassifyOptions {
  /** The widest range accepted, in host bits (MAX_HOST_BITS; the organization may set less). */
  maxHostBits?: number
}

/** The format of one typed entry. */
export function classifyTarget(raw: string, opts: ClassifyOptions = {}): ClassifiedTarget {
  const maxHostBits = Math.min(Math.max(opts.maxHostBits ?? MAX_HOST_BITS, 0), MAX_HOST_BITS)
  const input = raw.trim()
  const refuse = (id: keyof typeof REASONS, kind: TargetKind = 'invalid'): ClassifiedTarget => ({
    input,
    value: input,
    kind,
    reason: REASONS[id],
    reasonKey: `scans.targetReason.${id}`,
  })
  if (!input) return refuse('empty')
  if (looksLikeRepo(input)) return refuse('repo', 'repo')

  if (/^https?:\/\//i.test(input)) {
    if (/[\s<>"'`\\]/.test(input)) return refuse('urlChars')
    try {
      const url = new URL(input)
      if (!url.hostname) return refuse('noHost')
      return { input, value: input, kind: 'url' }
    } catch {
      return refuse('badUrl')
    }
  }

  // [v6]:port, the one place a bracket belongs.
  const v6Port = /^\[([^\]]+)\]:(\d{1,7})$/.exec(input)
  if (v6Port) {
    if (!isIPv6(v6Port[1])) return refuse('targetChars')
    if (!validPort(v6Port[2])) return refuse('badHostPort')
    return { input, value: input.toLowerCase(), kind: 'host:port' }
  }
  if (UNSAFE.test(input) || input.includes('[') || input.includes(']')) {
    return refuse('targetChars')
  }

  const trimmedDot = input.replace(/\.$/, '')
  // A service name: host:port/tcp or host:port/udp.
  const service = /^(.+):(\d{1,5})\/(tcp|udp)$/i.exec(trimmedDot)
  if (service) {
    const host = toAsciiHost(service[1])
    if (host && validPort(service[2]) && (DOMAIN.test(host) || IPV4.test(host))) {
      return {
        input,
        value: `${host}:${service[2]}/${service[3].toLowerCase()}`,
        kind: 'host:port',
      }
    }
    return refuse('badHostPort')
  }

  if (trimmedDot.startsWith('*.')) {
    const host = toAsciiHost(trimmedDot.slice(2))
    if (host && punycodeTld(host)) return refuse('idnTld')
    return host && DOMAIN.test(host)
      ? { input, value: `*.${host}`, kind: 'wildcard' }
      : refuse('wildcardForm')
  }

  const lower = trimmedDot.toLowerCase()
  if (IPV4.test(lower)) return { input, value: lower, kind: 'ipv4' }
  if (lower.includes('/')) {
    const [addr, bits, ...rest] = lower.split('/')
    if (rest.length === 0 && /^\d{1,3}$/.test(bits ?? '')) {
      const n = Number(bits)
      if (IPV4.test(addr) && n <= 32) {
        return 32 - n > maxHostBits
          ? tooLarge(input, lower, 32, n, maxHostBits)
          : { input, value: lower, kind: 'cidr' }
      }
      if (isIPv6(addr) && n <= 128) {
        return 128 - n > maxHostBits
          ? tooLarge(input, lower, 128, n, maxHostBits)
          : { input, value: lower, kind: 'cidr' }
      }
      return refuse('badCidr')
    }
    // More than one slash, or one that is not a prefix length after an
    // address: a path or a repository (the API refuses it the same way).
    if (lower.split('/').length > 2 || !IPV4.test(addr)) return refuse('repo', 'repo')
    return refuse('badCidr')
  }
  if (isIPv6(lower)) return { input, value: lower, kind: 'ipv6' }
  const hp = /^(.+):(\d{1,5})$/.exec(lower)
  if (hp) {
    const host = toAsciiHost(hp[1])
    if (
      host &&
      validPort(hp[2]) &&
      (DOMAIN.test(host) || IPV4.test(host) || host === 'localhost')
    ) {
      return { input, value: `${host}:${hp[2]}`, kind: 'host:port' }
    }
    return refuse('badHostPort')
  }
  const host = toAsciiHost(lower)
  if (host && punycodeTld(host)) return refuse('idnTld')
  if (host && DOMAIN.test(host)) return { input, value: host, kind: 'domain' }
  return refuse('unknown')
}

/**
 * The address count of a CIDR target, or null when it is not one. Large
 * counts stay exact (IPv6).
 */
export function cidrAddressCount(target: string): bigint | null {
  const [addr, len] = target.trim().toLowerCase().split('/')
  if (!addr || !/^\d{1,3}$/.test(len ?? '')) return null
  const total = IPV4.test(addr) ? 32 : isIPv6(addr) ? 128 : 0
  const n = Number(len)
  if (!total || n > total) return null
  return BigInt(1) << BigInt(total - n)
}

/** Whether a target is a range wider than a /16 (IPv6 /112): a large range. */
export function isLargeRange(target: string): boolean {
  const n = cidrAddressCount(target)
  return n !== null && n > BigInt(1) << BigInt(LARGE_RANGE_HOST_BITS)
}

/** Why an entry is not added, in the active language, with its numbers. */
export function targetReasonText(t: Translate, entry: ClassifiedTarget): string {
  if (!entry.reasonKey) return entry.reason ?? ''
  return t(entry.reasonKey, entry.reason, entry.reasonVars)
}

/** The key two entries are the same target by: the sent form, or the typed one lower-cased. */
export function targetKey(raw: string): string {
  const c = classifyTarget(raw)
  return isRefusedKind(c.kind) ? c.input.toLowerCase() : c.value.toLowerCase()
}

export interface PastedTargets {
  /** Every non-empty entry, classified, in order. */
  lines: ClassifiedTarget[]
  /** Valid targets, normalized, without repeats. */
  targets: string[]
  /** Entries that are not added: invalid ones and paths or repositories. */
  invalid: ClassifiedTarget[]
  /** Entries that repeat an earlier target. */
  duplicates: number
  /** Those entries, as typed. */
  duplicateInputs: string[]
  /** Targets of each kind (repeats counted once), and entries not added by kind. */
  byKind: Partial<Record<TargetKind, number>>
}

/** A `#` starts a comment at the start of a line or after a space (not inside a URL). */
function withoutComment(line: string): string {
  const i = line.search(/(^|\s)#/)
  return i < 0 ? line : line.slice(0, i)
}

/** The entries of typed or pasted lines: comments removed, split on commas, semicolons and spaces. */
export function splitEntries(lines: readonly string[]): string[] {
  return lines
    .flatMap((line) => withoutComment(line).split(/[,;\s]+/))
    .map((s) => s.trim())
    .filter(Boolean)
}

/** Classify, normalize and de-duplicate typed lines. */
export function parsePastedTargets(lines: readonly string[]): PastedTargets {
  const out: PastedTargets = {
    lines: [],
    targets: [],
    invalid: [],
    duplicates: 0,
    duplicateInputs: [],
    byKind: {},
  }
  const seen = new Set<string>()
  for (const raw of splitEntries(lines)) {
    const c = classifyTarget(raw)
    out.lines.push(c)
    if (isRefusedKind(c.kind)) {
      out.byKind[c.kind] = (out.byKind[c.kind] ?? 0) + 1
      out.invalid.push(c)
      continue
    }
    const key = c.value.toLowerCase()
    if (seen.has(key)) {
      out.duplicates++
      out.duplicateInputs.push(c.input)
      continue
    }
    seen.add(key)
    out.byKind[c.kind] = (out.byKind[c.kind] ?? 0) + 1
    out.targets.push(c.value)
  }
  return out
}

/**
 * The lines with every entry whose key (targetKey) is in `keys` removed; an
 * entry inside a line of several stays with its neighbours. Lines left empty
 * are dropped.
 */
export function withoutTargets(lines: readonly string[], keys: readonly string[]): string[] {
  const drop = new Set(keys.map((k) => k.trim().toLowerCase()))
  const out: string[] = []
  for (const line of lines) {
    const entries = splitEntries([line])
    const kept = entries.filter((e) => !drop.has(targetKey(e)))
    if (kept.length === entries.length) {
      if (entries.length > 0) out.push(line)
    } else if (kept.length > 0) {
      out.push(kept.join(', '))
    }
  }
  return out
}

/** The text of a CSV cell, quotes removed. */
function csvCell(cell: string): string {
  const c = cell.trim()
  return c.length >= 2 && c.startsWith('"') && c.endsWith('"')
    ? c.slice(1, -1).replace(/""/g, '"').trim()
    : c
}

function isTarget(entry: string): boolean {
  return entry !== '' && !isRefusedKind(classifyTarget(entry).kind)
}

/**
 * The entries of an uploaded `.txt` or `.csv` file. A text file is read line
 * by line. A CSV keeps the columns that mostly hold targets (other columns,
 * such as an owner or a note, are left out), and drops a first row with no
 * target in it (a header).
 */
export function targetFileLines(text: string, fileName: string): string[] {
  const rows = text.split(/\r?\n/).filter((r) => r.trim() !== '')
  if (!/\.csv$/i.test(fileName)) return rows.map((r) => r.trim())
  let cells = rows.map((r) => r.split(',').map(csvCell))
  if (cells.length > 1 && !cells[0].some(isTarget)) cells = cells.slice(1)
  const width = Math.max(0, ...cells.map((r) => r.length))
  const columns: number[] = []
  for (let col = 0; col < width; col++) {
    const filled = cells.map((r) => r[col] ?? '').filter(Boolean)
    const good = filled.filter(isTarget).length
    if (filled.length > 0 && good * 2 >= filled.length) columns.push(col)
  }
  const use = columns.length > 0 ? columns : Array.from({ length: width }, (_, i) => i)
  return cells.flatMap((r) => use.map((col) => r[col] ?? '')).filter(Boolean)
}

/**
 * The lines with the first entry typed exactly as `input` replaced by `next`
 * (an entry inside a line of several stays with its neighbours).
 */
export function replaceEntryInLines(
  lines: readonly string[],
  input: string,
  next: string
): string[] {
  let done = false
  return lines.map((line) => {
    if (done) return line
    const entries = splitEntries([line])
    const i = entries.indexOf(input)
    if (i < 0) return line
    done = true
    if (entries.length === 1) return next
    entries[i] = next
    return entries.join(', ')
  })
}
