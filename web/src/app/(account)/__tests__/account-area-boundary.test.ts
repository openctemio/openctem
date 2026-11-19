/**
 * The account area shows nothing of an organization (api RFC-141): its pages
 * and its shell never mount the organization's providers or read tenant data,
 * so they render the same for a person with no organization and for one an
 * organization does not admit yet. A direct-import guard over the area's own
 * files: a page that needs organization data belongs in the organization's
 * settings ("Your membership"), not here.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

import { ACCOUNT_NAV } from '@/config/account-nav'
import { ACCOUNT_ONLY_PAGES } from '@/lib/middleware/config'

const SRC = path.resolve(__dirname, '../../..')
const AREA = path.resolve(__dirname, '..')

/** Imports that bring in an organization: its providers, permissions or data. */
const FORBIDDEN = [
  '@/context/tenant-provider',
  '@/lib/permissions',
  '@/components/layout/app-sidebar',
  '@/components/layout/team-switcher',
  '@/features/organization/components/leave-organization',
  '@/features/findings/api/use-quick-views',
  '@/features/notifications/api/use-notification-api',
  '@/features/mcp-oauth',
]

function filesUnder(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name)
    if (statSync(full).isDirectory()) return name === '__tests__' ? [] : filesUnder(full)
    return /\.tsx?$/.test(name) ? [full] : []
  })
}

const AREA_FILES = [
  ...filesUnder(AREA),
  path.join(SRC, 'features/account/components/account-shell.tsx'),
  path.join(SRC, 'features/account/components/organizations-hub.tsx'),
  path.join(SRC, 'features/account/components/memberships-card.tsx'),
]

describe('the account area', () => {
  it.each(AREA_FILES.map((f) => [path.relative(SRC, f), f]))(
    '%s imports nothing of an organization',
    (_name, file) => {
      const source = readFileSync(file, 'utf8')
      const imports = [...source.matchAll(/from\s+'([^']+)'/g)].map((m) => m[1])
      for (const forbidden of FORBIDDEN) {
        expect(imports.filter((i) => i === forbidden || i.startsWith(`${forbidden}/`))).toEqual([])
      }
    }
  )

  it('has a page for every navigation item, and the proxy opens each for any session', () => {
    for (const item of ACCOUNT_NAV) {
      const page =
        item.url === '/account'
          ? path.join(AREA, 'account/page.tsx')
          : path.join(AREA, `${item.url.slice(1)}/page.tsx`)
      expect(statSync(page).isFile(), item.url).toBe(true)
      expect(ACCOUNT_ONLY_PAGES as readonly string[]).toContain(item.url)
    }
    expect([...ACCOUNT_ONLY_PAGES].sort()).toEqual(ACCOUNT_NAV.map((i) => i.url).sort())
  })
})
