import fs from 'node:fs'
import path from 'node:path'
import { adminNav } from '../../src/features/admin-console/config/admin-nav'

const APP = path.resolve(__dirname, '../../src/app/(console)')

/** Routes of the console shell, from its page files: a new page is visited the day it is added. */
export function pageRoutes(): string[] {
  const out: string[] = []
  const walk = (dir: string, segs: string[]) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!e.isDirectory()) {
        if (e.name === 'page.tsx') out.push('/' + segs.filter(Boolean).join('/'))
        continue
      }
      if (e.name.startsWith('_') || e.name === '__tests__' || e.name.startsWith('@')) continue
      const seg = /^\(.*\)$/.test(e.name) ? '' : e.name
      walk(path.join(dir, e.name), [...segs, seg])
    }
  }
  walk(APP, [])
  return [...new Set(out)].sort()
}

/** Every URL of the navigation config (sidebar and command palette), so a moved page is followed. */
export function navRoutes(): { title: string; url: string }[] {
  return adminNav.flatMap((s) => s.items.map((i) => ({ title: i.title, url: i.url })))
}

/**
 * Pages with a path parameter, opened on the first row of the list that
 * leads to them. `list` is read through the console's own proxy.
 */
export const DETAIL_ROUTES: {
  route: string
  list: string
  id: (row: Record<string, unknown>) => unknown
}[] = [
  { route: '/organizations/{id}', list: '/api/v1/admin/tenants?per_page=1', id: (r) => r.id },
  { route: '/users/{id}', list: '/api/v1/admin/platform-users?per_page=1', id: (r) => r.id },
]

/** The static routes the specs visit: every page file without a path parameter. */
export function staticRoutes(): string[] {
  return pageRoutes().filter((r) => !r.includes('['))
}

/** Page files with a path parameter, as a route pattern ("/users/[userId]" -> "/users/{id}"). */
export function dynamicPatterns(): string[] {
  return pageRoutes()
    .filter((r) => r.includes('['))
    .map((r) => r.replace(/\[[^\]]+\]/g, '{id}'))
}
