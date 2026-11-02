import { describe, expect, it } from 'vitest'
import { adminNav } from '../config/admin-nav'
import {
  activeNavUrl,
  isSettingsRailPath,
  mainNavSections,
  settingsRailSections,
  visibleAdminNav,
} from '../lib/admin-nav-visibility'
import type { AdminIdentity } from '../types'

const owner: AdminIdentity = {
  id: 'a',
  email: 'a@x',
  name: 'A',
  role: 'readonly',
  max_role: 'super_admin',
}

describe('console navigation groups', () => {
  it('groups the main sidebar by what the operator is doing', () => {
    expect(mainNavSections(adminNav).map((s) => s.title ?? '')).toEqual([
      '',
      'Customers',
      'Sensors and scanning',
      'Security and audit',
      'Monitoring',
    ])
  })

  it('puts instance-wide settings in the settings rail, grouped by subject', () => {
    expect(settingsRailSections(adminNav).map((s) => s.title)).toEqual([
      'General',
      'Sign-in and sign-up',
      'Organizations',
      'Scanning',
      'Notifications',
      'AI',
    ])
  })

  it('keeps the main sidebar short and lists every page exactly once', () => {
    const main = mainNavSections(adminNav).flatMap((s) => s.items.filter((i) => !i.hideInSidebar))
    expect(main.length).toBeLessThanOrEqual(20)
    const urls = adminNav.flatMap((s) => s.items.map((i) => i.url))
    expect(new Set(urls).size).toBe(urls.length)
  })

  it('files scanning policies under settings and what operators run under scanning', () => {
    const rail = settingsRailSections(adminNav).flatMap((s) => s.items.map((i) => i.url))
    expect(rail).toEqual(
      expect.arrayContaining([
        '/system/scan-approval',
        '/system/scan-identification',
        '/scanning/platform',
      ])
    )
    const scanning = adminNav
      .find((s) => s.title === 'Sensors and scanning')!
      .items.map((i) => i.url)
    expect(scanning).toEqual(
      expect.arrayContaining(['/scanning/target-mappings', '/system/threat-intel'])
    )
  })

  it('keeps the audit trail and four-eyes approvals first under Security and audit', () => {
    const security = adminNav.find((s) => s.title === 'Security and audit')!.items.map((i) => i.url)
    expect(security.slice(0, 2)).toEqual(['/security/activity', '/security/approvals'])
  })

  it('personal security keys stay searchable but leave the sidebar sections', () => {
    const keys = visibleAdminNav({ id: 'a', email: 'a@x', name: 'A', role: 'readonly' })
      .flatMap((s) => s.items)
      .find((i) => i.url === '/security/keys')
    expect(keys?.hideInSidebar).toBe(true)
  })

  it('marks the deepest entry and knows the settings rail pages', () => {
    const visible = visibleAdminNav(owner)
    expect(activeNavUrl('/requests/sign-ups', visible)).toBe('/requests/sign-ups')
    expect(activeNavUrl('/organizations/abc', visible)).toBe('/organizations')
    expect(isSettingsRailPath('/system/email', visible)).toBe(true)
    expect(isSettingsRailPath('/scanning/platform', visible)).toBe(true)
    expect(isSettingsRailPath('/system/announcements', visible)).toBe(false)
    expect(isSettingsRailPath('/', visible)).toBe(false)
  })
})
