import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SectionTabs } from '../section-tabs'
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
    // Same strip as TabsList: scrolls sideways, never vertically.
    expect(nav).toHaveClass('overflow-x-auto', 'overflow-y-hidden')
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
    ['/assets/suggestions', 'Suggestions'],
  ])('Assets: %s marks %s current, not Inventory', (path, tab) => {
    pathname = path
    render(<SectionTabs tabs={ASSETS_SECTION_TABS} />)
    expect(screen.getByRole('link', { name: tab })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('link', { name: 'Inventory' })).not.toHaveAttribute('aria-current')
  })
})
