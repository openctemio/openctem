/**
 * Display masking for text a list shows (a finding title, a location, a rule
 * id, a group label): whatever a scanner, an importer or a person wrote there,
 * a row never shows an e-mail address, a URL credential or a secret in clear.
 *
 * It mirrors the server's display masking (`server/pkg/safetext` `MaskEmails`
 * and `RedactSecrets`, and the preview of
 * `server/pkg/domain/vulnerability/secret_preview.go`). The server stays the
 * authority for what it stores and returns; this is the list's display-layer
 * guarantee only. Nothing is revealed from here: "Show" is on the finding
 * page.
 *
 * What is masked
 *
 * - E-mail addresses: the local part becomes `***`, the domain stays
 *   (`jane.doe@example.com` reads `***@example.com`; a URL-encoded
 *   `jane%40example.com` too). The domain needs two labels and an alphabetic
 *   top label, so `lib@1.2.3` and `image@sha256:...` are left alone.
 * - URL credentials: `scheme://user:pass@host` reads `scheme://••••••••@host`.
 * - Secrets, as a preview: at most the first and last 4 characters (never
 *   more than a quarter of the value at each end) around `••••••••`:
 *   a 20-character access key id reads `AKIA••••••••MPLE`.
 *   - known formats: AWS access key ids, JSON Web Tokens, GitHub, GitLab,
 *     Slack, Stripe live and Google tokens;
 *   - the body of a private key block (the header line stays);
 *   - the token after `Bearer` or an `Authorization` header;
 *   - the value of `password=`, `secret=`, `token=`, `api_key=` and their
 *     relatives. After `=` or in quotes the value is always masked. After a
 *     bare `:` (or `Bearer`) a plain word is left alone, because titles are
 *     prose ("Weak password: reuse allowed", "Bearer authentication missing");
 *   - any other run of 32 or more letters and digits that mixes lower case,
 *     upper case and at least two digits.
 *
 * What stays readable (the list needs it)
 *
 * - CVE, CWE and GHSA ids, UUIDs, version numbers, host names, paths.
 * - Hashes and digests in one case (a commit, an image digest, a rule id that
 *   is a hash): hexadecimal in one case is never taken for a secret.
 *
 * Properties: pure, never throws (on an internal error it returns the mask,
 * not the text), idempotent (masked text passes unchanged, so a value masked
 * where the row is built and again in a cell reads the same), and linear in
 * the length of the text: every quantifier is bounded and long values are
 * walked by hand.
 */

import { redactUrlCredentials } from '@/lib/redact-url'

/** What replaces the hidden part of a secret. */
export const SECRET_MASK = '••••••••'
/** What replaces the local part of an e-mail address (the server's `EmailMask`). */
export const EMAIL_MASK = '***'

/** The most characters of a secret shown at each end of its preview. */
const PREVIEW_ENDS = 4

/** The preview of a secret value: its ends around the mask. */
function preview(value: string): string {
  const chars = Array.from(value)
  const show = Math.min(PREVIEW_ENDS, Math.floor(chars.length / 4))
  if (show === 0) return SECRET_MASK
  return `${chars.slice(0, show).join('')}${SECRET_MASK}${chars.slice(-show).join('')}`
}

// \u2022 is the mask's bullet.
const OWN_PREVIEW = /^[^\u2022]{0,4}\u2022{3,16}[^\u2022]{0,4}$/
const SERVER_PREVIEW = /^[^…]{0,4}…[^…]{0,4}$/
const MASK_WORD = /^(?:\[REDACTED\]|\*{3})/i

/** Whether a value is already a mask: this module's preview, the server's, `[REDACTED]`, `***`. */
function isMasked(value: string): boolean {
  if (value.length <= 40 && (OWN_PREVIEW.test(value) || SERVER_PREVIEW.test(value))) return true
  return MASK_WORD.test(value)
}

const PLAIN_WORD = /^[A-Za-z]{1,23}(?:[-'][A-Za-z]{1,23}){0,3}[.,;:!?)\]]{0,3}$/

/** A word of prose (letters, a hyphen), not a token: no digit, under 24 characters. */
function isPlainWord(value: string): boolean {
  return value.length < 24 && PLAIN_WORD.test(value)
}

interface ValueRule {
  /** Global; every quantifier bounded; its LAST group is the value and ends the match. */
  re: RegExp
  /** One character that still belongs to the value past the bounded match. */
  tail?: RegExp
  /** Return false to leave this value as it is. */
  accept?: (value: string, match: RegExpExecArray) => boolean
}

/** Replace each value a rule finds with its preview. */
function maskValues(text: string, rule: ValueRule): string {
  const { re, tail, accept } = rule
  re.lastIndex = 0
  let out = ''
  let prev = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const matched = m[m.length - 1] ?? ''
    let end = m.index + m[0].length
    const start = end - matched.length
    if (tail) {
      while (end < text.length && tail.test(text.charAt(end))) end++
    }
    re.lastIndex = Math.max(end, m.index + 1)
    const value = text.slice(start, end)
    if (value === '' || isMasked(value) || (accept && !accept(value, m))) continue
    out += text.slice(prev, start) + preview(value)
    prev = end
  }
  return prev === 0 ? text : out + text.slice(prev)
}

// ---------------------------------------------------------------------------
// Private key blocks
// ---------------------------------------------------------------------------

const PEM_HEADER = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/g
const PEM_FOOTER = /-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/g
const KEY_CHAR = /[A-Za-z0-9+/=]/
const SPACE_CHAR = /\s/
/** A run this long after a header is key material, not the next word of a sentence. */
const KEY_RUN_MIN = 16

/** Where the key material after a header with no footer ends. */
function openKeyEnd(text: string, from: number): number {
  let end = from
  for (;;) {
    let i = end
    while (i < text.length && SPACE_CHAR.test(text.charAt(i))) i++
    let j = i
    while (j < text.length && KEY_CHAR.test(text.charAt(j))) j++
    if (j - i < KEY_RUN_MIN) return end
    end = j
  }
}

function maskPrivateKeys(text: string): string {
  if (!text.includes('PRIVATE KEY-----')) return text
  PEM_HEADER.lastIndex = 0
  let out = ''
  let prev = 0
  let footerGone = false
  let m: RegExpExecArray | null
  while ((m = PEM_HEADER.exec(text)) !== null) {
    const bodyStart = m.index + m[0].length
    // Already masked: leave the header and whatever follows it alone.
    if (text.startsWith(SECRET_MASK, bodyStart)) continue
    let end = bodyStart
    if (!footerGone) {
      PEM_FOOTER.lastIndex = bodyStart
      const f = PEM_FOOTER.exec(text)
      if (f) end = f.index + f[0].length
      else footerGone = true
    }
    if (end === bodyStart) end = openKeyEnd(text, bodyStart)
    if (end === bodyStart) continue
    out += text.slice(prev, bodyStart) + SECRET_MASK
    prev = end
    PEM_HEADER.lastIndex = end
  }
  return prev === 0 ? text : out + text.slice(prev)
}

// ---------------------------------------------------------------------------
// E-mail addresses
// ---------------------------------------------------------------------------

// The server's emailDomain, with the label count bounded.
const AT_DOMAIN =
  /(?:@|%40)(?=(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,32}[A-Za-z]{2,63}\b)/g
const LOCAL_CHAR = /[A-Za-z0-9._%+-]/

function maskEmails(text: string): string {
  if (!text.includes('@') && !text.includes('%40')) return text
  AT_DOMAIN.lastIndex = 0
  let out = ''
  let prev = 0
  let m: RegExpExecArray | null
  while ((m = AT_DOMAIN.exec(text)) !== null) {
    const at = m.index
    // The local part: walked back by hand, never past the previous address.
    let start = at
    while (start > prev && LOCAL_CHAR.test(text.charAt(start - 1))) start--
    if (start === at) continue
    out += text.slice(prev, start) + EMAIL_MASK
    prev = at
  }
  return prev === 0 ? text : out + text.slice(prev)
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

const WORD_TAIL = /[0-9A-Za-z_]/
const DASH_TAIL = /[0-9A-Za-z_-]/

const RULES: ValueRule[] = [
  // "Bearer <token>" and an Authorization header value.
  {
    re: /\b(?:authorization["']?\s{0,8}[:=]\s{0,8}["']?(?:(?:bearer|basic|token|negotiate|ntlm)\s{1,8})?|bearer\s{1,8})([A-Za-z0-9\-._~+/]{8,256}={0,8})/gi,
    tail: /[A-Za-z0-9\-._~+/=]/,
    accept: (value) => !isPlainWord(value),
  },
  // key = value, key: value, "key": "value", ?key=value. Groups: separator,
  // opening quote, value.
  {
    re: /(?:api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|(?:access|refresh|id|auth)[_-]?token|secret|password|passwd|pwd|token|auth)\b["']?\s{0,8}([:=])\s{0,8}(["']?)([^\s'"]{4,256})/gi,
    tail: /[^\s'"]/,
    accept: (value, m) => m[1] === '=' || m[2] !== '' || !isPlainWord(value),
  },
  // AWS access key ids (long-term, temporary and the other principal prefixes).
  { re: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16})\b/g },
  // JSON Web Tokens.
  {
    re: /\b(eyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048})/g,
    tail: DASH_TAIL,
  },
  // GitHub tokens: classic, OAuth, user-to-server, server-to-server, refresh, fine-grained.
  { re: /\b(gh[pousr]_[0-9A-Za-z_]{20,256})/g, tail: WORD_TAIL },
  { re: /\b(github_pat_[0-9A-Za-z_]{20,256})/g, tail: WORD_TAIL },
  // GitLab personal access tokens.
  { re: /\b(glpat-[0-9A-Za-z_-]{20,256})/g, tail: DASH_TAIL },
  // Slack tokens and app-level tokens.
  { re: /\b(xox[abeprs]-[0-9A-Za-z-]{10,256})/g, tail: DASH_TAIL },
  { re: /\b(xapp-[0-9A-Za-z-]{10,256})/g, tail: DASH_TAIL },
  // Stripe live secret and restricted keys.
  { re: /\b([sr]k_live_[0-9A-Za-z]{10,256})/g, tail: WORD_TAIL },
  // Google API keys and OAuth access tokens.
  { re: /\b(AIza[0-9A-Za-z_-]{35})/g, tail: DASH_TAIL },
  { re: /\b(ya29\.[0-9A-Za-z_-]{20,256})/g, tail: DASH_TAIL },
  // Anything else long and mixed: lower case, upper case and two digits.
  {
    re: /([A-Za-z0-9]{32,256})/g,
    tail: /[A-Za-z0-9]/,
    accept: (value) =>
      /[a-z]/.test(value) && /[A-Z]/.test(value) && (value.match(/[0-9]/g)?.length ?? 0) >= 2,
  },
]

/**
 * The text as a list may show it: e-mail addresses, URL credentials and
 * secrets masked (see the file comment for the exact rules). Mask BEFORE
 * cutting the text for display: a value cut in half no longer has the shape
 * that identifies it.
 */
export function maskSensitiveText(text: string | null | undefined): string {
  if (text === null || text === undefined) return ''
  try {
    let out = String(text)
    if (out.length < 4) return out
    out = maskPrivateKeys(out)
    out = redactUrlCredentials(out, SECRET_MASK)
    out = maskEmails(out)
    for (const rule of RULES) out = maskValues(out, rule)
    return out
  } catch {
    // Fail closed: an unreadable row is better than a leaked value.
    return SECRET_MASK
  }
}

/** Whether a text holds a secret preview made here (it cannot be typed back). */
export function hasSecretMask(text: string | null | undefined): boolean {
  return (text ?? '').includes(SECRET_MASK)
}
