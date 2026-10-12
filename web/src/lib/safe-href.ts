/**
 * URL output encoding for data-driven links and images.
 *
 * Scanner references, asset URLs, evidence URIs, notification links and
 * integration hosts all come from data an attacker can influence (a hostile
 * scan target, a compromised sensor, a tenant member). Rendered as a raw
 * `href`, a `javascript:` or `data:` value becomes a clickable script; a
 * protocol-relative `//host` silently leaves the app. Every data-driven
 * `href` and `src` goes through the helpers in this file instead; the guard
 * test `src/lib/__tests__/raw-href-guard.test.ts` fails the build on a new
 * raw one.
 *
 * Design: RFC-040 (platform/sensor mutual distrust), section 5.4.
 */

/** Longest URL we will turn into a link. Anything longer is not a real reference. */
export const MAX_URL_LENGTH = 4096

/** Schemes a data-driven link may use. */
const LINK_PROTOCOLS = new Set(['http:', 'https:'])

/**
 * Bidi controls and invisible formatting characters. A URL that carries one
 * displays differently from where it points (Trojan Source), so it is refused.
 */
const FORBIDDEN_CHARS_RE =
  /[\u0000-\u001f\u007f-\u009f\u061C\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/

/** A leading scheme, e.g. `https:` or `javascript:`. */
const SCHEME_RE = /^([a-z][a-z0-9+.-]*):/i

/** A bare host such as `github.com/x/y` that a scanner reported without a scheme. */
const BARE_HOST_RE =
  /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+(?::\d{1,5})?(?:[/?#]|$)/i

export interface SafeHrefOptions {
  /**
   * Allow same-origin paths (`/findings/1`, `?tab=x`, `#anchor`). On by
   * default: the API serves attachments and internal links as paths.
   * Protocol-relative `//host` and `/\host` are never treated as paths.
   */
  allowRelative?: boolean
  /** Allow `mailto:` links. Off by default. */
  allowMailto?: boolean
}

/**
 * Remove what the WHATWG URL parser itself ignores, so the string we check is
 * the string the browser navigates to: leading/trailing C0 controls and
 * spaces, and tab/CR/LF anywhere (`java\tscript:` is `javascript:`).
 */
function normalise(raw: string): string {
  return raw.replace(/^[\u0000- ]+|[\u0000- ]+$/g, '').replace(/[\t\n\r]/g, '')
}

function isSameOriginPath(url: string): boolean {
  if (url.startsWith('#') || url.startsWith('?')) return true
  if (!url.startsWith('/')) return false
  // Browsers treat `\` as `/` for http(s), so `/\evil.test` is `//evil.test`.
  const second = url.charAt(1)
  return second !== '/' && second !== '\\'
}

/**
 * Return a URL that is safe to put in an `href`, or `undefined` when it is not.
 *
 * Allowed: `http:` and `https:` URLs (normalised by the URL parser), bare
 * hosts such as `example.com/x` (given `https:`), same-origin paths when
 * `allowRelative` (default), and `mailto:` when `allowMailto`.
 *
 * Refused: every other scheme (`javascript:`, `data:`, `vbscript:`, `file:`,
 * `blob:` …) including obfuscated spellings (case, embedded tabs/newlines,
 * leading control characters, entity- or percent-encoded schemes, which
 * fail to parse), protocol-relative URLs, URLs with control or bidi
 * characters, and URLs longer than {@link MAX_URL_LENGTH}.
 */
export function safeHref(url: unknown, options: SafeHrefOptions = {}): string | undefined {
  const { allowRelative = true, allowMailto = false } = options
  if (typeof url !== 'string') return undefined
  const cleaned = normalise(url)
  if (cleaned === '' || cleaned.length > MAX_URL_LENGTH) return undefined
  if (FORBIDDEN_CHARS_RE.test(cleaned)) return undefined

  if (isSameOriginPath(cleaned)) return allowRelative ? cleaned : undefined
  if (cleaned.startsWith('/') || cleaned.startsWith('\\')) return undefined

  let candidate = cleaned
  const scheme = SCHEME_RE.exec(cleaned)
  if (!scheme) {
    // No scheme: only a plain host name may be promoted to https. Anything
    // else (`&#106;avascript:…`, `%6Aavascript:…`, `./x`) is refused.
    if (!BARE_HOST_RE.test(cleaned)) return undefined
    candidate = `https://${cleaned}`
  } else if (BARE_HOST_RE.test(cleaned) && /^\d/.test(cleaned.slice(scheme[0].length))) {
    // `example.com:8443/x` parses as scheme "example.com"; it is a host and port.
    candidate = `https://${cleaned}`
  }

  let parsed: URL
  try {
    parsed = new URL(candidate)
  } catch {
    return undefined
  }
  if (LINK_PROTOCOLS.has(parsed.protocol)) {
    if (!parsed.hostname) return undefined
    return parsed.href
  }
  if (allowMailto && parsed.protocol === 'mailto:') return parsed.href
  return undefined
}

/** Raster image types an `<img>` may load from a `data:` URL (no SVG). */
const SAFE_DATA_IMAGE_RE =
  /^data:image\/(?:png|jpe?g|gif|webp|avif|bmp|x-icon);base64,[a-z0-9+/=\s]+$/i

/**
 * Return a value that is safe for an image `src`, or `undefined`.
 *
 * Allows what {@link safeHref} allows (http(s) and same-origin paths), plus
 * base64 `data:` raster images (uploaded logos) and `blob:` object URLs
 * created by this page (upload previews). SVG data URLs are refused.
 */
export function safeImageSrc(url: unknown): string | undefined {
  if (typeof url !== 'string') return undefined
  const cleaned = normalise(url)
  if (/^data:/i.test(cleaned)) return SAFE_DATA_IMAGE_RE.test(cleaned) ? cleaned : undefined
  if (/^blob:/i.test(cleaned)) {
    if (typeof window === 'undefined') return undefined
    return cleaned.startsWith(`blob:${window.location.origin}/`) ? cleaned : undefined
  }
  return safeHref(cleaned)
}

/**
 * Hosts a profile picture may load from. A person's picture is shown to
 * teammates, so an arbitrary host could log their IP addresses and browsers
 * (a tracking pixel). Same list as the API (api/pkg/domain/user/avatar.go),
 * which refuses other hosts on input; this guard covers stored values.
 */
const AVATAR_HOSTS = new Set([
  'avatars.githubusercontent.com',
  'secure.gravatar.com',
  'www.gravatar.com',
  'gitlab.com',
])
const AVATAR_HOST_SUFFIXES = ['.googleusercontent.com']

/**
 * Return a profile picture URL that is safe to load, or `undefined` (the
 * avatar then shows initials): https only, no credentials or port, on a
 * known avatar host.
 */
export function safeAvatarSrc(url: unknown): string | undefined {
  if (typeof url !== 'string' || url === '') return undefined
  const cleaned = normalise(url)
  if (cleaned.length > MAX_URL_LENGTH || FORBIDDEN_CHARS_RE.test(cleaned)) return undefined
  let parsed: URL
  try {
    parsed = new URL(cleaned)
  } catch {
    return undefined
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port) {
    return undefined
  }
  const host = parsed.hostname.toLowerCase()
  const allowed =
    AVATAR_HOSTS.has(host) ||
    AVATAR_HOST_SUFFIXES.some((s) => host.endsWith(s) && host.length > s.length)
  return allowed ? parsed.href : undefined
}

/**
 * Return a same-origin path for an in-app `<Link>`, or `undefined`. Use it
 * where the path comes from the server (notification targets) rather than
 * from a route builder: an absolute or protocol-relative URL is refused, so
 * the link cannot leave the app.
 */
export function safeInternalHref(path: unknown): string | undefined {
  if (typeof path !== 'string') return undefined
  const cleaned = normalise(path)
  if (cleaned.length > MAX_URL_LENGTH || FORBIDDEN_CHARS_RE.test(cleaned)) return undefined
  return isSameOriginPath(cleaned) ? cleaned : undefined
}
