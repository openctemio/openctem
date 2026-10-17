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

/** Repeated slashes collapsed, "." and ".." resolved, no trailing slash. */
function cleanPath(p: string): string {
  const out: string[] = []
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') out.pop()
    else out.push(seg)
  }
  return '/' + out.join('/')
}

/**
 * The ways a request path can be read (as written, and percent-decoded),
 * each cleaned, and whether it carries an encoded separator ("%2f", "%2e",
 * "%5c", a backslash): spelling the path differently must not cross a plane.
 */
function readings(pathname: string): { forms: string[]; encodedSeparator: boolean } {
  let encodedSeparator = /%2f|%2e|%5c/i.test(pathname) || pathname.includes('\\')
  let decoded = pathname
  try {
    decoded = decodeURIComponent(pathname)
  } catch {
    encodedSeparator = true
  }
  return { forms: [cleanPath(pathname), cleanPath(decoded)], encodedSeparator }
}

const isConsolePath = (p: string) => under(p, '/admin') || under(p, '/api/v1/admin')

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
  const { forms, encodedSeparator } = readings(pathname)
  if (plane === 'admin') {
    // Only the console: every reading of the path, with no encoded separator.
    if (!encodedSeparator && forms.every(isConsolePath)) return 'allow'
    if (!encodedSeparator && forms.every((f) => f === '/api/health')) return 'allow'
    if (forms[0] === '/' && forms[1] === '/') return 'to-console'
    return 'not-found'
  }
  // Never the console: any reading of the path that reaches it.
  const maybeConsole = forms.some(isConsolePath) || (encodedSeparator && /admin/i.test(pathname))
  return maybeConsole ? 'not-found' : 'allow'
}
