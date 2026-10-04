/**
 * Display rules for attacker-influenced strings (research 20 §5).
 *
 * Targets, host names, URLs, tool names and tool or sensor error messages can
 * be shaped by whoever controls a scanned system (a banner, a crafted DNS
 * name, an error that echoes a response). React already escapes them, so they
 * can never run as markup; what is left is spoofing and layout:
 *
 * - Bidi controls (U+202A–202E, U+2066–2069, LRM/RLM/ALM) can flip how the
 *   rest of a row reads (a U+202E inside a host name makes the rest read backwards).
 * - Line breaks and other control characters can fake a second row or hide
 *   text.
 * - A megabyte message can freeze the page.
 *
 * `toDisplayText` makes every such character visible as an escape and caps
 * the length. It never decodes, links or interprets anything.
 */

/** Characters shown as `\u{…}` escapes instead of being applied. */
const BIDI_CONTROLS = new RegExp('[\\u061C\\u200E\\u200F\\u202A-\\u202E\\u2066-\\u2069]', 'g')
// C0 and C1 controls other than tab, LF and CR (handled first), DEL, the
// zero-width characters that hide text, and the Unicode line separators.
const OTHER_CONTROLS = new RegExp(
  '[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F-\\u009F\\u200B-\\u200D\\u2028\\u2029\\uFEFF]',
  'g'
)

/** The most characters of one value ever rendered. */
export const MAX_DISPLAY_CHARS = 2000

function escapeChar(ch: string): string {
  return `\\u{${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}}`
}

/**
 * The value as it is safe to show: line breaks become a visible "⏎", tabs a
 * space, bidi and other control characters visible `\u{XXXX}` escapes, and
 * anything past `max` characters is cut with "…".
 */
export function toDisplayText(value: unknown, max: number = MAX_DISPLAY_CHARS): string {
  if (value === null || value === undefined) return ''
  let s = String(value)
  // Cut before escaping so a huge value costs nothing; a cut in the middle of
  // a surrogate pair drops the lone half.
  let cut = false
  if (s.length > max) {
    s = s.slice(0, max).replace(/[\uD800-\uDBFF]$/, '')
    cut = true
  }
  s = s
    .replace(/\r\n|\r|\n/g, ' ⏎ ')
    .replace(/\t/g, ' ')
    .replace(BIDI_CONTROLS, escapeChar)
    .replace(OTHER_CONTROLS, escapeChar)
  return cut ? `${s}…` : s
}

/** Whether the value carries a character that `toDisplayText` neutralises. */
export function hasHiddenCharacters(value: string): boolean {
  return (
    /\r|\n/.test(value) ||
    new RegExp(BIDI_CONTROLS.source).test(value) ||
    new RegExp(OTHER_CONTROLS.source).test(value)
  )
}
