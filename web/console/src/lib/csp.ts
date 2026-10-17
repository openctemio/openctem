/**
 * The console's Content-Security-Policy: stricter than the tenant app's.
 * Scripts only from this origin with the request's nonce, no third-party
 * script, styles and fonts only from this origin, requests only to this
 * origin, nothing may frame it, no plugin, no <base>, forms only to itself.
 * The one exception is the sign-in CAPTCHA's frame, which the API asks for
 * only after repeated failed sign-ins and only when the operator configured it.
 */

export function buildConsoleCsp(nonce: string, isDev: boolean): string {
  const script = [`'self'`, `'nonce-${nonce}'`, `'strict-dynamic'`]
  if (isDev) script.push(`'unsafe-eval'`) // React refresh
  return [
    "default-src 'self'",
    `script-src ${script.join(' ')}`,
    "style-src 'self' 'unsafe-inline'",
    // The brand logo may be an operator-configured https URL; images run no code.
    "img-src 'self' data: https:",
    "font-src 'self' data:",
    isDev ? "connect-src 'self' ws: wss:" : "connect-src 'self'",
    "object-src 'none'",
    'frame-src https://challenges.cloudflare.com',
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'",
  ].join('; ')
}
