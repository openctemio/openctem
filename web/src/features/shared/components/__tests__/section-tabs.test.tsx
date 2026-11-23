import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SectionTabs, iconsFit, stripIconsAllowed } from '../section-tabs'
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
    // One swipe row: tabs that do not fit scroll sideways with an edge fade,
    // never wrap and never fold into a More menu.
    expect(nav).toHaveClass('overflow-x-auto')
    expect(nav).toHaveAttribute('data-tab-strip')
    expect(screen.queryByText('More')).toBeNull()
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

  it('reads the count unit after the visible label and number, with no aria-label', () => {
    const units = { '/account/security': 'sessions open' }
    const { rerender } = render(
      <SectionTabs tabs={tabs} counts={{ '/account/security': 3 }} countUnits={units} />
    )
    // Label in name: the visible text ("Security 3") is the start of the name.
    const link = screen.getByRole('link', { name: /^Security\s*3\s*sessions open$/ })
    expect(link).not.toHaveAttribute('aria-label')
    expect(link.querySelector('[data-slot=tabs-count]')).toHaveTextContent('3')
    expect(link.querySelector('.sr-only')).toHaveTextContent('sessions open')
    rerender(<SectionTabs tabs={tabs} counts={{ '/account/security': 0 }} countUnits={units} />)
    const plain = screen.getByRole('link', { name: 'Security' })
    expect(plain.querySelector('[data-slot=tabs-count]')).toBeNull()
    expect(plain.querySelector('.sr-only')).toBeNull()
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

describe('iconsFit', () => {
  // Four tabs of 60px, 24px gaps: 312px with no icons, 400px with icons.
  const w = [60, 60, 60, 60]
  it('draws the icons when every tab fits with its icon', () => {
    expect(iconsFit(w, 400, 24, true)).toBe(true)
  })
  it('drops the icons when they do not fit (the strip then swipes)', () => {
    expect(iconsFit(w, 399, 24, true)).toBe(false)
  })
  it('never draws icons the strip does not allow', () => {
    expect(iconsFit(w, 1000, 24, false)).toBe(false)
  })
})
