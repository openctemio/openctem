/**
 * Every in-app link written as a literal in src/ opens a page that exists.
 *
 * Collects the string literals that are navigation targets (`href`, `url`,
 * `*Href` / `*Url` / `*Path` values, `router.push/replace/prefetch`,
 * `redirect`, `permanentRedirect`, `location.href/assign/replace`) and starts
 * with "/", and resolves each against the routes in src/app: route groups
 * `(x)` and parallel slots `@x` are not path segments, `[id]` matches any
 * segment, `[...x]` / `[[...x]]` the rest of the path. A `${...}` segment of
 * a template literal matches any segment. A link to a retired route that
 * src/config/legacy-routes.ts redirects counts as valid (legacy-routes.test.ts
 * checks that the redirect lands on a page).
 *
 * A target only known at run time, that this test cannot resolve, carries the
 * marker `route-links: ignore` in a comment on the same line.
 */
import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

import { resolveLegacyRoute } from '../legacy-routes'

const SRC = join(__dirname, '..', '..')
const APP = join(SRC, 'app')
const MARKER = 'route-links: ignore'

/** Route patterns, one array of segments per page, route handler or metadata route. */
function collectRoutes(dir: string, segs: string[], out: string[][]): string[][] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      if (entry.startsWith('_') || entry === '__tests__') continue
      const routing = (entry.startsWith('(') && entry.endsWith(')')) || entry.startsWith('@')
      collectRoutes(full, routing ? segs : [...segs, entry], out)
    } else if (/^(page|route)\.tsx?$/.test(entry)) {
      out.push(segs)
    } else if (/^(icon|apple-icon|opengraph-image|sitemap|robots|manifest)\.\w+$/.test(entry)) {
      out.push([...segs, entry.replace(/\.\w+$/, '').replace(/^(sitemap|robots)$/, '$1.xml')])
    }
  }
  return out
}

const ROUTES = collectRoutes(APP, [], [])

function matches(route: string[], segs: string[]): boolean {
  for (let i = 0; i < route.length; i++) {
    const r = route[i]
    if (/^\[\[\.\.\..+\]\]$/.test(r)) return true
    if (/^\[\.\.\..+\]$/.test(r)) return segs.length > i
    if (i >= segs.length) return false
    const s = segs[i]
    if (r.startsWith('[') || s.includes('${') || r === s) continue
    return false
  }
  return route.length === segs.length
}

function routeExists(url: string): boolean {
  const path = url.split(/[?#]/)[0]
  const segs = path.split('/').filter(Boolean)
  return ROUTES.some((r) => matches(r, segs))
}

const CONTEXTS = [
  // href="/x", href={'/x'}, href: '/x', url: `/x`, settingsHref = '/x', ...
  String.raw`\b(?:href|url|[A-Za-z]+(?:Href|Url|URL|Path))\s*[:=]\s*\{?\s*`,
  String.raw`\b(?:router|navigation)\.(?:push|replace|prefetch)\(\s*`,
  String.raw`(?:^|[^.\w])(?:redirect|permanentRedirect)\(\s*`,
  String.raw`\blocation\.(?:href\s*=|assign\(|replace\()\s*`,
]
const LITERAL =
  String.raw`(?:(['"])(\/[^'"\s]*)\1|` + '`' + String.raw`(\/[^` + '`' + String.raw`\s]*)` + '`)'
const TARGET = new RegExp(`(?:${CONTEXTS.join('|')})${LITERAL}`, 'g')

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '__tests__' || name === 'generated') continue
    const full = join(dir, name)
    if (statSync(full).isDirectory()) sourceFiles(full, out)
    else if (/\.tsx?$/.test(name) && !/\.(test|spec)\.tsx?$/.test(name)) out.push(full)
  }
  return out
}

/** Files whose "/x" values are redirect rules or route patterns, not links. */
const SKIP = new Set([
  'config/legacy-routes.ts',
  'config/legacy-sensor-routes.ts',
  'config/route-permissions.ts',
])

interface Link {
  where: string
  url: string
}

function collectLinks(): Link[] {
  const links: Link[] = []
  for (const file of sourceFiles(SRC)) {
    const rel = relative(SRC, file)
    if (SKIP.has(rel)) continue
    const lines = readFileSync(file, 'utf8').split('\n')
    lines.forEach((line, i) => {
      const trimmed = line.trim()
      if (trimmed.startsWith('*') || trimmed.startsWith('//') || line.includes(MARKER)) return
      for (const m of line.matchAll(TARGET)) {
        const url = m[2] ?? m[3]
        if (!url || url.startsWith('//') || url.startsWith('/api/')) continue
        links.push({ where: `${rel}:${i + 1}`, url })
      }
    })
  }
  return links
}

describe('in-app links', () => {
  const links = collectLinks()

  it('finds the links (the extractor still works)', () => {
    expect(links.length).toBeGreaterThan(100)
    expect(links.some((l) => l.url === '/findings')).toBe(true)
  })

  it('resolves routes the way Next.js does', () => {
    expect(routeExists('/findings')).toBe(true)
    expect(routeExists('/findings/abc?tab=x')).toBe(true)
    expect(routeExists('/settings/members')).toBe(true)
    expect(routeExists('/pentest')).toBe(false)
    expect(routeExists('/no-such-page')).toBe(false)
    expect(routeExists('/assets/${id}')).toBe(true)
  })

  it('every literal link opens an existing page or a known redirect', () => {
    const broken = links
      .filter(
        (l) =>
          !routeExists(l.url) && resolveLegacyRoute(l.url.replace(/\$\{[^}]*\}/g, 'x')) === null
      )
      .map((l) => `${l.where}  ${l.url}`)
    expect(broken, 'links to a route that does not exist').toEqual([])
  })
})
