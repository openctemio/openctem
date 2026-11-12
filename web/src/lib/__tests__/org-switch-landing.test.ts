/**
 * After a switch of organization no address of the previous one survives:
 * every page of the app, opened with a record id of the old organization and
 * a query, lands on a page without any id and without a query.
 */
import { describe, expect, it } from 'vitest'
import { readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import {
  DYNAMIC_PAGE_ROUTES,
  STATIC_BESIDE_DYNAMIC,
  isOrgNeutralAddress,
  orgSwitchLanding,
} from '@/lib/org-switch-landing'
import { PATHS_WITHOUT_PAGE } from '@/components/layout/breadcrumb-routes'

const APP_DIR = join(process.cwd(), 'src', 'app')
const OLD_ORG_ID = '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'

/** Every page route in src/app: route groups removed, dynamic segments as [id]. */
function pageRoutes(dir = APP_DIR, segments: string[] = [], out = new Set<string>()) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) {
      if (name === 'api' && segments.length === 0) continue
      const next = /^\(.*\)$/.test(name)
        ? segments
        : [...segments, /^\[.*\]$/.test(name) ? '[id]' : name]
      pageRoutes(full, next, out)
    } else if (name === 'page.tsx') {
      out.add('/' + segments.join('/'))
    }
  }
  return out
}

const pages = pageRoutes()
const staticPages = new Set([...pages].filter((p) => !p.includes('[id]')))

describe('DYNAMIC_PAGE_ROUTES', () => {
  it('lists exactly the page routes of src/app with a dynamic segment', () => {
    const dynamic = [...pages].filter((p) => p.includes('[id]')).sort()
    expect([...DYNAMIC_PAGE_ROUTES].sort()).toEqual(dynamic)
  })
})

describe('STATIC_BESIDE_DYNAMIC', () => {
  it('lists the static page segments that sit beside a dynamic one', () => {
    const expected: Record<string, string[]> = {}
    for (const route of pages) {
      const segs = route.split('/').filter(Boolean)
      segs.forEach((seg, i) => {
        if (seg !== '[id]') return
        const parent = '/' + segs.slice(0, i).join('/')
        const kids = new Set<string>()
        for (const p of pages) {
          const s = p.split('/').filter(Boolean)
          if (s.length > i && '/' + s.slice(0, i).join('/') === parent && s[i] !== '[id]') {
            kids.add(s[i])
          }
        }
        if (kids.size > 0) expected[parent] = [...kids].sort()
      })
    }
    const actual = Object.fromEntries(
      Object.entries(STATIC_BESIDE_DYNAMIC).map(([k, v]) => [k, [...v].sort()])
    )
    expect(actual).toEqual(expected)
  })
})

describe('orgSwitchLanding', () => {
  it.each([...pages].sort())('%s lands on a page with no id of the old organization', (route) => {
    const path = route.replaceAll('[id]', OLD_ORG_ID)
    const landing = orgSwitchLanding(`${path}?page=5&asset_id=${OLD_ORG_ID}`)
    expect(landing).not.toContain(OLD_ORG_ID)
    expect(landing).not.toContain('?')
    expect(landing).not.toContain('[id]')
    expect(landing === '/' || staticPages.has(landing)).toBe(true)
    expect(PATHS_WITHOUT_PAGE.has(landing)).toBe(false)
    // A landing is final: switching again from it stays there.
    expect(orgSwitchLanding(landing)).toBe(landing)
    expect(isOrgNeutralAddress(landing, '')).toBe(true)
  })

  it('keeps the section: the list root of a detail page', () => {
    expect(orgSwitchLanding(`/findings/${OLD_ORG_ID}`)).toBe('/findings')
    expect(orgSwitchLanding(`/assets/groups/${OLD_ORG_ID}`)).toBe('/assets/groups')
    expect(orgSwitchLanding(`/pentest/campaigns/${OLD_ORG_ID}`)).toBe('/pentest/campaigns')
    expect(orgSwitchLanding(`/scans/${OLD_ORG_ID}`)).toBe('/scans')
    expect(orgSwitchLanding('/findings')).toBe('/findings')
    expect(orgSwitchLanding('/findings/approvals')).toBe('/findings/approvals')
  })

  it('drops a dynamic segment that is not an id (a slug, a CVE)', () => {
    expect(orgSwitchLanding('/vulnerabilities/CVE-2024-3094')).toBe('/vulnerabilities')
    expect(orgSwitchLanding('/settings/integrations/import-mappings/main-mapping')).toBe(
      '/settings/integrations/import-mappings'
    )
  })

  it('never keeps an id in a path no route lists', () => {
    expect(orgSwitchLanding(`/no-such-page/${OLD_ORG_ID}/x`)).toBe('/no-such-page')
  })

  it('goes to the dashboard when the section has no page of its own', () => {
    expect(orgSwitchLanding(`/pentest/findings/${OLD_ORG_ID}/edit`)).toBe('/')
    expect(orgSwitchLanding('')).toBe('/')
  })
})

describe('isOrgNeutralAddress', () => {
  it('is false for a list with its page, filters or an open record', () => {
    expect(isOrgNeutralAddress('/findings', 'page=5')).toBe(false)
    expect(isOrgNeutralAddress('/findings', `?selected=${OLD_ORG_ID}`)).toBe(false)
    expect(isOrgNeutralAddress(`/findings/${OLD_ORG_ID}`, '')).toBe(false)
  })

  it('is true for a list root without a query', () => {
    expect(isOrgNeutralAddress('/findings', '')).toBe(true)
    expect(isOrgNeutralAddress('/', '')).toBe(true)
  })
})
