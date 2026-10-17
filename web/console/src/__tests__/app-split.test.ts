/**
 * @vitest-environment node
 *
 * The tenant app and the platform console are separate apps (RFC-022
 * revision 21): the tenant app has no console route, page or proxy, and the
 * console has only its own routes, at the root of its site.
 */
import fs from 'node:fs'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

const WEB = path.resolve(__dirname, '../../..')
const ROUTE_FILE = /^(page|route|layout)\.(ts|tsx|js|jsx)$/

/** Route paths of an app directory ("/path kind"), route groups dropped. */
function routes(appDir: string): string[] {
  const out: string[] = []
  const walk = (dir: string) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name)
      if (e.isDirectory()) {
        if (e.name !== '__tests__') walk(p)
      } else if (ROUTE_FILE.test(e.name)) {
        const rel = path
          .relative(appDir, dir)
          .split(path.sep)
          .filter((s) => s && !/^\(.*\)$/.test(s))
          .join('/')
        out.push(`/${rel} ${e.name.split('.')[0]}`)
      }
    }
  }
  walk(appDir)
  return out.sort()
}

/** Every non-test source file under dir. */
function sources(dir: string): string[] {
  const out: string[] = []
  const walk = (d: string) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name)
      if (e.isDirectory()) {
        if (e.name !== '__tests__' && e.name !== 'node_modules' && e.name !== '.next') walk(p)
      } else if (/\.(ts|tsx)$/.test(e.name) && !/\.test\.tsx?$/.test(e.name)) {
        out.push(p)
      }
    }
  }
  walk(dir)
  return out
}

describe('the tenant app', () => {
  const tenant = routes(path.join(WEB, 'src/app'))

  it('has no console page and no console API proxy', () => {
    expect(tenant.filter((r) => /^\/admin(\/| )/.test(r) || r.startsWith('/api/v1/admin'))).toEqual(
      []
    )
  })

  it('imports no console code', () => {
    const offenders = sources(path.join(WEB, 'src')).filter((f) =>
      /from ['"](@console\/|[./]+\/console\/src\/)/.test(fs.readFileSync(f, 'utf8'))
    )
    expect(offenders).toEqual([])
  })
})

describe('the console app', () => {
  const consoleRoutes = routes(path.join(WEB, 'console/src/app'))

  it('serves only its own routes, at the root of its site', () => {
    const allowed = [
      /^\/ (layout|page)$/,
      /^\/login(\/callback)? (layout|page)$/,
      /^\/(organizations|users|security|operations|system|scanning|requests|support)(\/[^ ]+)? (layout|page)$/,
      /^\/api\/health route$/,
      /^\/api\/v1\/admin\/\[\.\.\.path\] route$/,
    ]
    expect(consoleRoutes.filter((r) => !allowed.some((re) => re.test(r)))).toEqual([])
    expect(consoleRoutes).toContain('/ page')
    expect(consoleRoutes).toContain('/login page')
  })

  it('has no /admin path and no tenant API proxy', () => {
    expect(consoleRoutes.filter((r) => r.startsWith('/admin'))).toEqual([])
    expect(
      consoleRoutes.filter((r) => r.startsWith('/api/v1/') && !r.startsWith('/api/v1/admin/'))
    ).toEqual([])
  })

  it('imports no tenant route', () => {
    const offenders = sources(path.join(WEB, 'console/src')).filter((f) =>
      /from ['"]@\/app\/(?!providers['"])/.test(fs.readFileSync(f, 'utf8'))
    )
    expect(offenders).toEqual([])
  })
})
