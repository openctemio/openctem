import { describe, expect, it } from 'vitest'
import { adminNav } from '../config/admin-nav'
import { visibleAdminNav } from '../lib/admin-nav-visibility'

describe('console navigation groups', () => {
  it('groups pages by what the operator is doing', () => {
    expect(adminNav.map((s) => s.title ?? '')).toEqual([
      '',
      'Customers',
      'Scanning',
      'Security',
      'Settings',
      'Monitoring',
    ])
  })

  it('keeps every scanning page together', () => {
    const scanning = adminNav.find((s) => s.title === 'Scanning')!.items.map((i) => i.url)
    expect(scanning).toEqual(
      expect.arrayContaining([
        '/system/scan-approval',
        '/system/platform-scanning',
        '/system/shared-sensors',
        '/scanning/target-mappings',
      ])
    )
  })

  it('personal security keys stay searchable but leave the sidebar sections', () => {
    const keys = visibleAdminNav('readonly')
      .flatMap((s) => s.items)
      .find((i) => i.url === '/security/keys')
    expect(keys?.hideInSidebar).toBe(true)
  })
})
