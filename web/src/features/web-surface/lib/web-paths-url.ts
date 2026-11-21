/**
 * The path tree of a web origin (server/docs/architecture/web-surface.md,
 * "Path tree"): node paths, filters and the request URL of one level.
 *
 * A node is "/" or a path template without a trailing slash. It holds the
 * endpoints of its own template and of every template below it.
 */

export type PathScope = '' | 'in' | 'out'

export interface PathFilters {
  hideStatic: boolean
  hide4xx: boolean
  withFindings: boolean
  includeGone: boolean
  scope: PathScope
  method: string
  /** The search term, already debounced (useSearchQuery). */
  q: string
}

/** Static files are hidden by default; 4xx answers stay (a 403 admin path matters). */
export const DEFAULT_PATH_FILTERS: PathFilters = {
  hideStatic: true,
  hide4xx: false,
  withFindings: false,
  includeGone: false,
  scope: '',
  method: '',
  q: '',
}

export const PATH_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const

export interface PathLevelOptions {
  /** Only the node's own template, not what lies below it. */
  here?: boolean
  /** With here: the open findings at the node's own template. */
  findings?: boolean
  page?: number
  /** 0: the child nodes only. */
  perPage?: number
}

/** True when a filter other than the defaults hides something. */
export function pathFiltersChanged(f: PathFilters): boolean {
  return (
    f.hideStatic !== DEFAULT_PATH_FILTERS.hideStatic ||
    f.hide4xx ||
    f.withFindings ||
    f.includeGone ||
    f.scope !== '' ||
    f.method !== '' ||
    f.q !== ''
  )
}

/** A node path the API accepts: "/" or "/a/b" (no trailing or doubled slash). */
export function normalizeNodePath(raw: string | null | undefined): string {
  const p = (raw ?? '').trim()
  if (!p.startsWith('/') || p.includes('//') || /[?#\\]/.test(p) || p.length > 2048) return '/'
  return p.length > 1 && p.endsWith('/') ? p.slice(0, -1) : p
}

/** The URL of one level of an origin's path tree. */
export function webPathsUrl(
  assetId: string,
  path: string,
  f: PathFilters,
  o: PathLevelOptions = {}
): string {
  const p = new URLSearchParams()
  if (path !== '/') p.set('path', path)
  if (f.q) p.set('q', f.q)
  if (f.hideStatic) p.set('hide_static', 'true')
  if (f.hide4xx) p.set('hide_4xx', 'true')
  if (f.withFindings) p.set('with_findings', 'true')
  if (f.includeGone) p.set('include_gone', 'true')
  if (f.scope) p.set('scope', f.scope)
  if (f.method) p.set('method', f.method)
  if (o.here) p.set('here', 'true')
  if (o.findings) p.set('findings', 'true')
  if (o.page && o.page > 1) p.set('page', String(o.page))
  p.set('per_page', String(o.perPage ?? 50))
  return `/api/v1/assets/${encodeURIComponent(assetId)}/web-paths?${p.toString()}`
}

/** The parent of a node ("/" for a top-level node and for the root). */
export function parentPath(path: string): string {
  const i = path.lastIndexOf('/')
  return i <= 0 ? '/' : path.slice(0, i)
}

/** The nodes from the root down to path: [{name, path}], root excluded. */
export function pathTrail(path: string): { name: string; path: string }[] {
  if (path === '/') return []
  const out: { name: string; path: string }[] = []
  let acc = ''
  for (const seg of path.slice(1).split('/')) {
    acc += `/${seg}`
    out.push({ name: seg, path: acc })
  }
  return out
}

/** A variable segment of a template ({int}, {uuid}, ...). */
export function isParamSegment(name: string): boolean {
  return name.startsWith('{') && name.endsWith('}')
}

/**
 * A template as shown under the selected node: the part below the node after
 * an ellipsis ("…/{int}/history" under /api/v1/orders), the last segment of
 * the node itself ("…/orders"), the whole template at the root.
 */
export function pathUnder(template: string, node: string): string {
  if (node === '/' || !template.startsWith(node)) return template
  if (template === node) return `\u2026${template.slice(template.lastIndexOf('/'))}`
  return `\u2026${template.slice(node.length)}`
}
