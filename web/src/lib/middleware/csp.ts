/**
 * Content-Security-Policy with a per-request script nonce.
 *
 * The proxy (src/proxy.ts) makes a fresh nonce for every request, puts the policy
 * on the request (Next.js reads the nonce from it and stamps it on its own
 * bootstrap and chunk scripts) and on the response. Every page is rendered
 * per request already (the root layout reads headers()), so no static HTML
 * is served with a stale nonce.
 *
 * script-src: `'nonce-…' 'strict-dynamic'` and no `'unsafe-inline'`: an
 * injected inline script or `javascript:` URL does not run. `'self'` stays as
 * the fallback for browsers without CSP3 (`'strict-dynamic'` makes CSP3
 * browsers ignore it). `'unsafe-eval'` only under `next dev` (HMR evaluates
 * modules at runtime).
 *
 * style-src keeps `'unsafe-inline'`: React `style={…}` attributes, Radix and
 * sonner set inline styles, which a nonce cannot cover. CSS cannot run script.
 *
 * img-src keeps `https:`: tool logos and SCM avatars come from arbitrary
 * hosts. Narrowing it needs an image proxy; the URLs themselves go through
 * safeImageSrc (src/lib/safe-href.ts).
 *
 * CAPTCHA (Cloudflare Turnstile): only the pages that show the widget
 * (CAPTCHA_ROUTES) also allow https://challenges.cloudflare.com for scripts,
 * frames and connections. Every other page keeps frame-src 'none' and no
 * third-party origin. The widget script is added by our own (nonce-trusted)
 * code, which 'strict-dynamic' allows; the host entry is the CSP2 fallback.
 *
 * Design: RFC-040 (platform/sensor mutual distrust), section 5.4.
 */

/** The Cloudflare Turnstile origin (script, challenge frame, verification). */
export const TURNSTILE_ORIGIN = 'https://challenges.cloudflare.com'

/** Pages that may show the CAPTCHA widget: request access and sign-up. */
export const CAPTCHA_ROUTES = ['/request-access', '/register'] as const

/** True for a CAPTCHA page or a page below it, on a path-segment boundary. */
export function isCaptchaRoute(pathname: string): boolean {
  return CAPTCHA_ROUTES.some((r) => pathname === r || pathname.startsWith(`${r}/`))
}

export interface CspOptions {
  nonce: string
  isDev: boolean
  /** NEXT_PUBLIC_APP_URL */
  appUrl?: string
  /** BACKEND_API_URL */
  backendUrl?: string
  /** NEXT_PUBLIC_WS_BASE_URL */
  wsUrl?: string
  /** Allow the Turnstile origin (set only for CAPTCHA_ROUTES). */
  captcha?: boolean
}

/** A 128-bit random nonce, base64. Works in the Node and Edge runtimes. */
export function generateNonce(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

function connectSrc({ isDev, appUrl, backendUrl, wsUrl, captcha }: CspOptions): string {
  if (isDev) return "connect-src 'self' http: ws: wss:" // HMR
  const origins: string[] = ["'self'"]
  if (captcha) origins.push(TURNSTILE_ORIGIN)
  if (appUrl) {
    try {
      const u = new URL(appUrl)
      origins.push(`https://${u.hostname}`, `wss://${u.hostname}`)
      // The API on another port of the same host (e.g. :8080).
      if (backendUrl) {
        const b = new URL(backendUrl)
        if (b.port && b.port !== '443') {
          origins.push(`https://${u.hostname}:${b.port}`, `wss://${u.hostname}:${b.port}`)
        }
      }
    } catch {
      /* ignore invalid URL */
    }
  }
  // WebSocket on a separate host/port (NEXT_PUBLIC_WS_BASE_URL).
  if (wsUrl) {
    try {
      const w = new URL(wsUrl)
      origins.push(`wss://${w.host}`, `https://${w.host}`)
    } catch {
      /* ignore invalid URL */
    }
  }
  // No URL configured: self-hosted, the backend's auth is the gate.
  if (origins.length === (captcha ? 2 : 1)) origins.push('https:', 'wss:')
  return `connect-src ${origins.join(' ')}`
}

export function buildCsp(options: CspOptions): string {
  const { nonce, isDev, captcha } = options
  const script = [`'self'`, `'nonce-${nonce}'`, `'strict-dynamic'`]
  if (captcha) script.push(TURNSTILE_ORIGIN)
  if (isDev) script.push(`'unsafe-eval'`)
  return [
    "default-src 'self'",
    `script-src ${script.join(' ')}`,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "img-src 'self' data: https:",
    "font-src 'self' data: https://fonts.gstatic.com",
    connectSrc(options),
    "object-src 'none'",
    captcha ? `frame-src ${TURNSTILE_ORIGIN}` : "frame-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ')
}

/** The policy for this request: this process's environment and the page. */
export function cspForRequest(nonce: string, pathname = ''): string {
  return buildCsp({
    nonce,
    captcha: isCaptchaRoute(pathname),
    isDev: process.env.NODE_ENV === 'development',
    appUrl: process.env.NEXT_PUBLIC_APP_URL,
    backendUrl: process.env.BACKEND_API_URL,
    wsUrl: process.env.NEXT_PUBLIC_WS_BASE_URL,
  })
}
