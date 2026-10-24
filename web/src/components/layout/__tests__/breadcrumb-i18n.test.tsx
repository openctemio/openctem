import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'
import en from '@/lib/i18n/dictionaries/en/nav.json'
import viDict from '@/lib/i18n/dictionaries/vi/nav.json'
import enSettings from '@/lib/i18n/dictionaries/en/settings.json'
import viSettings from '@/lib/i18n/dictionaries/vi/settings.json'
import { settingsNavItems } from '@/config/settings-nav'

const pathname = vi.hoisted(() => ({ current: '' }))
vi.mock('next/navigation', () => ({ usePathname: () => pathname.current }))

const { BreadcrumbNav } = await import('../breadcrumb-nav')
const { BREADCRUMB_OWN_KEYS, breadcrumbLabelKey, recordLabelKey } =
  await import('../breadcrumb-labels')

const enNav = en as Record<string, string>
const viNav = viDict as Record<string, string>

describe('breadcrumb labels in the reader language', () => {
  it('has an English and a Vietnamese string for every label the trail names itself', () => {
    for (const [key, label] of Object.entries(BREADCRUMB_OWN_KEYS)) {
      expect(enNav[key], key).toBe(label)
      expect(viNav[key], key).toBeTruthy()
    }
  })

  it('uses the keys the menus render with', () => {
    expect(breadcrumbLabelKey('/priority-rules', 'priority-rules')).toBe('nav.item.priority-rules')
    const scim = settingsNavItems.find((i) => i.url === '/settings/scim')!
    expect(breadcrumbLabelKey(scim.url, 'scim')).toBe(`settings.item.${scim.id}`)
    expect(breadcrumbLabelKey('/settings', 'settings')).toBe('nav.crumb.settings')
    expect(recordLabelKey('campaigns')).toBe('nav.record.campaigns')
    expect(recordLabelKey('unknown')).toBe('nav.record.details')
  })

  it('renders the trail in Vietnamese for a Vietnamese reader', () => {
    pathname.current = '/settings/members'
    render(
      <I18nProvider locale="vi">
        <BreadcrumbNav />
      </I18nProvider>
    )
    const members = settingsNavItems.find((i) => i.url === '/settings/members')!
    const viSet = viSettings as Record<string, string>
    const enSet = enSettings as Record<string, string>
    expect(screen.getByText(viNav['nav.crumb.settings'])).toBeInTheDocument()
    expect(screen.getByText(viSet[`settings.item.${members.id}`])).toBeInTheDocument()
    expect(screen.queryByText(enSet[`settings.item.${members.id}`])).not.toBeInTheDocument()
  })
})
