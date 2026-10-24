import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SectionTabs, fitTabs, stripIconsAllowed } from '../section-tabs'
import { Shield, User, Clock } from 'lucide-react'
import { ASSETS_SECTION_TABS } from '@/config/section-tabs'

let pathname = '/account'
vi.mock('next/navigation', () => ({ usePathname: () => pathname }))

const tabs = [
  { label: 'Profile', href: '/account' },
  { label: 'Security', href: '/account/security' },
  { label: 'Activity', href: '/account/activity' },
]

describe('SectionTabs', () => {
  beforeEach(() => {
    pathname = '/account'
  })

  it('renders route tabs as a labelled navigation with the shared strip', () => {
    render(<SectionTabs tabs={tabs} label="Account sections" />)
    const nav = screen.getByRole('navigation', { name: 'Account sections' })
    // Never scrolls: tabs that do not fit go to a More menu instead.
    expect(nav).toHaveClass('overflow-hidden')
    expect(nav).toHaveAttribute('data-slot', 'page-tabs')
    expect(screen.getAllByRole('link')).toHaveLength(3)
  })

  it('marks only the most specific matching tab as current', () => {
    pathname = '/account/security'
    render(<SectionTabs tabs={tabs} />)
    expect(screen.getByRole('link', { name: 'Security' })).toHaveAttribute('aria-current', 'page')
    // '/account' is a prefix of '/account/security' but is not the current tab.
    expect(screen.getByRole('link', { name: 'Profile' })).not.toHaveAttribute('aria-current')
  })

  it('keeps a tab current on its nested routes', () => {
    pathname = '/account/activity/2026-09'
    render(<SectionTabs tabs={tabs} />)
    expect(screen.getByRole('link', { name: 'Activity' })).toHaveAttribute('aria-current', 'page')
  })

  it.each([
    ['/assets/groups', 'Groups'],
    ['/assets/groups/abc', 'Groups'],
    ['/assets/attention/context', 'Needs attention'],
    // Relationships and duplicates are reasons of Needs attention at their own URLs.
    ['/assets/suggestions', 'Needs attention'],
    ['/assets/duplicates', 'Needs attention'],
  ])('Assets: %s marks %s current, not Inventory', (path, tab) => {
    pathname = path
    render(<SectionTabs tabs={ASSETS_SECTION_TABS} />)
    expect(screen.getByRole('link', { name: tab })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('link', { name: 'Inventory' })).not.toHaveAttribute('aria-current')
  })

  it('draws icons only when every tab has its own', () => {
    const iconTabs = [
      { label: 'Profile', href: '/account', icon: User },
      { label: 'Security', href: '/account/security', icon: Shield },
      { label: 'Activity', href: '/account/activity', icon: Clock },
    ]
    expect(stripIconsAllowed(iconTabs)).toBe(true)
    expect(stripIconsAllowed([iconTabs[0], iconTabs[1], tabs[2]])).toBe(false)
    expect(stripIconsAllowed([iconTabs[0], { ...iconTabs[1], icon: User }])).toBe(false)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { container } = render(<SectionTabs tabs={[iconTabs[0], iconTabs[1], tabs[2]]} />)
    expect(container.querySelectorAll('[data-slot=tab-icon]')).toHaveLength(0)
    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })
})

describe('fitTabs', () => {
  // Four tabs of 60px, 24px gaps: 312px with no icons, 400px with icons.
  const w = [60, 60, 60, 60]
  it('shows every tab with icons when they fit', () => {
    expect(fitTabs(w, 400, 70, 0, true)).toEqual({
      icons: true,
      visible: [0, 1, 2, 3],
      overflow: [],
    })
  })
  it('drops the icons before moving a tab to More', () => {
    expect(fitTabs(w, 320, 70, 0, true)).toEqual({
      icons: false,
      visible: [0, 1, 2, 3],
      overflow: [],
    })
  })
  it('moves the last tabs to More and keeps labels whole', () => {
    // room = 250 - 70 - 24 = 156: two tabs (144px).
    expect(fitTabs(w, 250, 70, 0, true)).toEqual({
      icons: false,
      visible: [0, 1],
      overflow: [2, 3],
    })
  })
  it('keeps the current tab in the strip when it would fall into More', () => {
    expect(fitTabs(w, 250, 70, 3, false)).toEqual({
      icons: false,
      visible: [0, 3],
      overflow: [1, 2],
    })
  })
  it('always shows at least the current tab', () => {
    expect(fitTabs([300, 300], 200, 70, 1, false).visible).toEqual([1])
  })
})
