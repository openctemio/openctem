/**
 * The platform console on its own origin (RFC-022 revision 20, the admin
 * plane). With OPENCTEM_ADMIN_PLANE=separate, the gateway's console site marks
 * every request it forwards with `X-OpenCTEM-Plane: admin` (and strips the
 * header from the main site's requests, so a client cannot set it). Then:
 *
 * - a console-site request may reach only the console: its pages (/admin...),
 *   its API proxy (/api/v1/admin...) and the health probe; `/` goes to
 *   /admin; anything else is 404, so no tenant page or tenant API runs on the
 *   console's origin;
 * - a main-site request never reaches the console: /admin... and
 *   /api/v1/admin... are 404.
 *
 * Unset (or `shared`): one origin for both, as before.
 */

export const ADMIN_PLANE_HEADER = 'x-openctem-plane'

export type PlaneDecision = 'allow' | 'not-found' | 'to-console'

function under(pathname: string, prefix: string): boolean {
  return pathname === prefix || pathname.startsWith(prefix + '/')
}

/** Whether the console has its own origin (OPENCTEM_ADMIN_PLANE=separate). */
export function adminPlaneSeparate(value: string | undefined = process.env.OPENCTEM_ADMIN_PLANE) {
  return value === 'separate'
}

/** What to do with a request for `pathname` that carries `plane` (the header). */
export function decidePlane(
  pathname: string,
  plane: string | null,
  separate: boolean = adminPlaneSeparate()
): PlaneDecision {
  if (!separate) return 'allow'
  const isConsole = under(pathname, '/admin') || under(pathname, '/api/v1/admin')
  if (plane === 'admin') {
    if (isConsole || pathname === '/api/health') return 'allow'
    if (pathname === '/') return 'to-console'
    return 'not-found'
  }
  return isConsole ? 'not-found' : 'allow'
}
