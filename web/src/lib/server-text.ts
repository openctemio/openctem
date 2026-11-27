/**
 * Text the server writes, shown in the reader's language.
 *
 * The server sends a stable message code and typed values next to its English
 * text (a notification's `message_code` + `message_params`, and the same pair
 * on other server-written sentences). This module renders the code from the
 * `serverText` catalog namespace (`serverText.<code>`, or `.title` / `.body`
 * for a two-part message) and falls back to the server's English text when the
 * catalog has no entry for the code, a nested code or the part, so a newer
 * server never shows a raw key and older rows (no code) read as before.
 *
 * Values are display text only. Strings are made safe with `toDisplayText`
 * (bidi and control characters visible, length capped) and are inserted after
 * the catalog string is resolved, so a value that looks like a placeholder
 * (`{count}`) or a plural block stays literal text. Nothing is ever parsed as
 * markup, a link or an instruction.
 *
 * Well-known values are worded from existing catalogs: `capability`
 * (assetCoverage.capability.*), `severity` and `*_severity`, `role` (org.role.*),
 * `finding_status` and `*_finding_status` (findings.status.*); a name ending in `_at` is a time
 * shown in the reader's locale. A nested `{ code, params }` value is a
 * message of its own (a reason, an action); `lines` is a list of messages,
 * one per line (a digest); any other list of messages reads as one phrase
 * joined by commas.
 */

import { formatAbsoluteTime } from '@/lib/format-metric'
import { toDisplayText } from '@/lib/untrusted-text'

export type TranslateVars = Record<string, string | number>
export type Translate = (key: string, fallback?: string, vars?: TranslateVars) => string

export interface ServerMessage {
  code: string
  params?: Record<string, unknown> | null
}

/** The catalog namespace of server-written text. */
export const SERVER_TEXT_NS = 'serverText'

/** The most characters of one inserted value. */
const MAX_VALUE_CHARS = 500
/** How deep nested messages may go (a digest line's reason is depth 2). */
const MAX_DEPTH = 3
/** The most lines of one digest. */
const MAX_LINES = 50

const CODE = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$/
// Private-use characters that mark where a value goes; stripped from values.
const MARK_OPEN = ''
const MARK_CLOSE = ''
const MARKS = /[]/g
const MISSING = 'missing'

/** Whether a value is a message: an object with a well-formed code. */
export function isServerMessage(v: unknown): v is ServerMessage {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false
  const code = (v as { code?: unknown }).code
  return typeof code === 'string' && code.length <= 96 && CODE.test(code)
}

/** One value as display text, or undefined when a nested code is unknown. */
function valueText(
  t: Translate,
  locale: string,
  name: string,
  v: unknown,
  depth: number
): string | number | undefined {
  if (isServerMessage(v)) return render(t, locale, v, undefined, depth + 1)
  if (typeof v === 'number') return Number.isFinite(v) ? v : ''
  if (typeof v === 'boolean') return String(v)
  if (typeof v !== 'string') return ''
  const raw = v.replace(MARKS, '')
  if (name === 'capability')
    return t(`assetCoverage.capability.${raw}`, toDisplayText(raw, MAX_VALUE_CHARS))
  if (name === 'severity' || name.endsWith('_severity'))
    return t(`severity.${raw.toLowerCase()}`, toDisplayText(raw, MAX_VALUE_CHARS))
  if (name === 'role') return t(`org.role.${raw}`, toDisplayText(raw, MAX_VALUE_CHARS))
  if (name === 'finding_status' || name.endsWith('_finding_status'))
    return t(`findings.status.${raw}`, toDisplayText(raw, MAX_VALUE_CHARS))
  if (name.endsWith('_at')) {
    const shown = formatAbsoluteTime(raw, locale)
    if (shown) return shown
  }
  return toDisplayText(raw, MAX_VALUE_CHARS)
}

function render(
  t: Translate,
  locale: string,
  msg: ServerMessage,
  part: 'title' | 'body' | undefined,
  depth: number
): string | undefined {
  if (depth > MAX_DEPTH) return undefined
  const key = `${SERVER_TEXT_NS}.${msg.code}${part ? `.${part}` : ''}`
  if (t(key, MISSING) === MISSING) return undefined

  const params = msg.params && typeof msg.params === 'object' ? msg.params : {}
  const vars: TranslateVars = {}
  const inserted: string[] = []
  for (const [name, v] of Object.entries(params)) {
    if (!/^\w{1,64}$/.test(name)) continue
    let shown: string | number | undefined
    if (name === 'lines' && Array.isArray(v)) {
      const lines: string[] = []
      for (const line of v.slice(0, MAX_LINES)) {
        if (!isServerMessage(line)) return undefined
        // A line is its message's body (or the message itself when it is a leaf).
        const text =
          render(t, locale, line, 'body', depth + 1) ??
          render(t, locale, line, undefined, depth + 1)
        if (text === undefined) return undefined
        lines.push(`- ${text}`)
      }
      shown = lines.join('\n')
    } else if (Array.isArray(v)) {
      // A list of messages (changed fields, reasons) reads as one phrase.
      const items: string[] = []
      for (const item of v.slice(0, MAX_LINES)) {
        const text = isServerMessage(item)
          ? render(t, locale, item, undefined, depth + 1)
          : undefined
        if (text === undefined) return undefined
        items.push(text)
      }
      shown = items.join(', ')
    } else {
      shown = valueText(t, locale, name, v, depth)
    }
    if (shown === undefined) return undefined
    if (typeof shown === 'number') {
      vars[name] = shown // counts select plural branches and are grouped by locale
    } else {
      vars[name] = `${MARK_OPEN}${inserted.length}${MARK_CLOSE}`
      inserted.push(shown)
    }
  }
  const text = t(key, '', vars)
  return text.replace(/(\d+)/g, (_, i: string) => inserted[Number(i)] ?? '')
}

/**
 * The text of a server message in the reader's language, or `fallback` (the
 * server's English text) when there is no message or the catalog does not
 * know it. `part` picks the title or body of a two-part message.
 */
export function serverText(
  t: Translate,
  locale: string,
  msg: ServerMessage | null | undefined,
  fallback: string,
  part?: 'title' | 'body'
): string {
  if (!isServerMessage(msg)) return fallback
  return render(t, locale, msg, part, 0) ?? fallback
}

/** Whether serverText would render the message from the catalog (not the fallback). */
export function hasServerText(
  t: Translate,
  locale: string,
  msg: ServerMessage | null | undefined,
  part?: 'title' | 'body'
): boolean {
  return isServerMessage(msg) && render(t, locale, msg, part, 0) !== undefined
}

/** A message from a payload's `<prefix>_code` and `<prefix>_params` fields. */
export function messageOf(code: unknown, params: unknown): ServerMessage | undefined {
  if (typeof code !== 'string' || !code) return undefined
  const m: ServerMessage = {
    code,
    params:
      params && typeof params === 'object' && !Array.isArray(params)
        ? (params as Record<string, unknown>)
        : undefined,
  }
  return isServerMessage(m) ? m : undefined
}
