/**
 * Pure helpers for the finding evidence viewer.
 *
 * Evidence is untrusted tool output (a response body can hold any HTML or
 * script). Nothing here produces markup: it splits text into segments the
 * viewer renders as React text, `<mark>` for the matched part, and chips for
 * the «secret:kind#n» placeholders the API masked.
 */

import type { EvidenceItem } from '@/lib/api/generated'

/** A masked value the API replaced; the same grammar as the API's. */
export const PLACEHOLDER_PATTERN = /«secret:[a-z_]{1,32}#[0-9]{1,4}»/g

export type Segment =
  | { kind: 'text'; text: string; mark: boolean }
  | { kind: 'secret'; placeholder: string; mark: boolean }

/** The UTF-16 index of a UTF-8 byte offset in s (the API counts bytes). */
export function byteToCharIndex(s: string, byteOffset: number): number {
  if (byteOffset <= 0) return 0
  let bytes = 0
  let i = 0
  while (i < s.length) {
    const cp = s.codePointAt(i)!
    const n = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4
    if (bytes + n > byteOffset) return i
    bytes += n
    i += cp > 0xffff ? 2 : 1
    if (bytes === byteOffset) return i
  }
  return s.length
}

/** Splits text into plain and placeholder segments, all with the same mark. */
export function splitPlaceholders(text: string, mark = false): Segment[] {
  const out: Segment[] = []
  let last = 0
  for (const m of text.matchAll(PLACEHOLDER_PATTERN)) {
    const at = m.index ?? 0
    if (at > last) out.push({ kind: 'text', text: text.slice(last, at), mark })
    out.push({ kind: 'secret', placeholder: m[0], mark })
    last = at + m[0].length
  }
  if (last < text.length) out.push({ kind: 'text', text: text.slice(last), mark })
  return out
}

/**
 * Splits a body into segments: the byte ranges (the API's match offsets) are
 * marked, placeholders become secret segments. Overlapping or invalid ranges
 * are merged or ignored.
 */
export function segmentBody(body: string, byteRanges: Array<[number, number]>): Segment[] {
  const ranges = byteRanges
    .filter(([s, e]) => Number.isFinite(s) && Number.isFinite(e) && e > s && s >= 0)
    .map(([s, e]) => [byteToCharIndex(body, s), byteToCharIndex(body, e)] as [number, number])
    .sort((a, b) => a[0] - b[0])
  const merged: Array<[number, number]> = []
  for (const r of ranges) {
    const prev = merged[merged.length - 1]
    if (prev && r[0] <= prev[1]) prev[1] = Math.max(prev[1], r[1])
    else merged.push([r[0], r[1]])
  }
  const out: Segment[] = []
  let pos = 0
  for (const [s, e] of merged) {
    if (s > pos) out.push(...splitPlaceholders(body.slice(pos, s), false))
    out.push(...splitPlaceholders(body.slice(s, e), true))
    pos = e
  }
  if (pos < body.length) out.push(...splitPlaceholders(body.slice(pos), false))
  return out
}

/** The body byte ranges the API marked for one side of an exchange. */
export function bodyRanges(
  item: EvidenceItem,
  location: 'request' | 'response'
): Array<[number, number]> {
  return (item.match ?? [])
    .filter(
      (m) =>
        m.location === location &&
        m.part === 'body' &&
        typeof m.start === 'number' &&
        typeof m.end === 'number'
    )
    .map((m) => [m.start as number, m.end as number])
}

/** Whether a whole part (status line, headers, URL) is what matched. */
export function partMatched(
  item: EvidenceItem,
  location: 'request' | 'response',
  part: 'status' | 'header' | 'url'
): boolean {
  return (item.match ?? []).some((m) => m.location === location && m.part === part)
}

/** Every placeholder in an item, in order of first appearance. */
export function placeholdersOf(item: EvidenceItem): string[] {
  const seen = new Set<string>()
  const found = JSON.stringify(item).match(PLACEHOLDER_PATTERN) ?? []
  for (const p of found) seen.add(p)
  return [...seen]
}

/** The request as raw HTTP text (masked), for copy and download. */
export function rawRequestText(item: EvidenceItem): string {
  const q = item.http?.request
  if (!q) return ''
  let target = q.url ?? ''
  try {
    const u = new URL(target)
    target = u.pathname + u.search
  } catch {
    // not an absolute URL: keep it as sent
  }
  const lines = [`${q.method || 'GET'} ${target} ${q.http_version || 'HTTP/1.1'}`]
  for (const h of q.headers ?? []) lines.push(`${h.name}: ${h.value}`)
  return `${lines.join('\r\n')}\r\n\r\n${q.body ?? ''}`
}

/** The response as raw HTTP text (masked), for copy and download. */
export function rawResponseText(item: EvidenceItem): string {
  const s = item.http?.response
  if (!s) return ''
  const lines = [`${s.http_version || 'HTTP/1.1'} ${s.status ?? ''} ${s.reason ?? ''}`.trimEnd()]
  for (const h of s.headers ?? []) lines.push(`${h.name}: ${h.value}`)
  return `${lines.join('\r\n')}\r\n\r\n${s.body ?? ''}`
}

/**
 * Puts revealed values in place of their placeholders. In a shell command
 * (shellQuoted) every placeholder sits inside single quotes, so a value's own
 * single quotes are escaped the POSIX way and cannot end the argument.
 */
export function substitute(
  text: string,
  values: Record<string, string>,
  shellQuoted = false
): string {
  return text.replace(PLACEHOLDER_PATTERN, (p) => {
    const v = values[p]
    if (v === undefined) return p
    return shellQuoted ? v.replaceAll("'", `'\\''`) : v
  })
}

/** A short, readable kind name. */
export function kindLabel(kind: string): string {
  switch (kind) {
    case 'http_exchange':
      return 'HTTP exchange'
    case 'raw_text':
      return 'Raw output'
    case 'command_output':
      return 'Command output'
    case 'file_excerpt':
      return 'File excerpt'
    case 'curl':
      return 'Reproduction'
    case 'screenshot':
      return 'Screenshot'
    default:
      return kind
  }
}
