/**
 * Attack surface navigation: one tab row (owner rule 2026-11-24, one tab level
 * per screen). The row lists the section's tabs in order with its own labels,
 * no segmented lens under it, and Posture is not a tab: the Overview stays
 * active on it.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'

const nav = vi.hoisted(() => ({ path: '/attack-surface' }))

vi.mock('next/navigation', () => ({
  usePathname: () => nav.path,
  useRouter: () => ({ push: vi.fn() }),
}))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, useVisibleSectionTabs: <T,>(tabs: readonly T[]) => tabs }
})
vi.mock('../../hooks/use-easm-suggestions', () => ({ useEASMSuggestionCount: () => 3 }))

const { AttackSurfaceSectionTabs } = await import('../attack-surface-section-tabs')

const tabNames = () =>
  within(screen.getByRole('navigation', { name: 'Attack surface sections' }))
    .getAllByRole('link')
    .map((a) => (a.textContent ?? '').replace(/\d+$/, '').trim())

beforeEach(() => {
  nav.path = '/attack-surface'
})

describe('AttackSurfaceSectionTabs', () => {
  it('draws one row in order, with no lens and no Posture tab', () => {
    render(<AttackSurfaceSectionTabs />)
    expect(tabNames()).toEqual([
      'Overview',
      'Technologies',
      'Certificates',
      'Web surface',
      'Exposures',
      'Lookalikes',
      'Changes',
      'Page changes',
      'Discovery',
      'Review',
    ])
    expect(screen.queryByTestId('segmented-lens')).toBeNull()
  })

  it('keeps the Overview active on the Posture page', () => {
    nav.path = '/attack-surface/posture'
    render(<AttackSurfaceSectionTabs />)
    expect(screen.getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page')
  })

  it('marks the open tab', () => {
    nav.path = '/attack-surface/pages'
    render(<AttackSurfaceSectionTabs />)
    expect(screen.getByRole('link', { name: 'Page changes' })).toHaveAttribute(
      'aria-current',
      'page'
    )
  })
})
