/**
 * Browser binding for federated sign-in (SSO and social).
 *
 * The API returns a one-time secret when it starts a sign-in and refuses the
 * callback unless the same secret comes back, so a callback URL (code + state)
 * that leaks to another browser is useless. The secret lives in an HttpOnly
 * cookie of the browser that started the sign-in. SameSite=Lax because the
 * identity provider returns with a top-level GET. The `__Host-` prefix pins
 * the cookie to this origin and needs Secure, so it is dropped only where
 * cookies are not Secure (plain-HTTP development).
 */

export type BindingKind = 'sso' | 'oauth'

function isSecure(): boolean {
  return process.env.SECURE_COOKIES !== 'false'
}

export function bindingCookieName(kind: BindingKind): string {
  return isSecure() ? `__Host-${kind}_binding` : `${kind}_binding`
}

export function bindingCookieOptions() {
  return {
    httpOnly: true,
    secure: isSecure(),
    sameSite: 'lax' as const,
    maxAge: 600, // 10 minutes, as long as the API keeps the state
    path: '/',
  }
}
