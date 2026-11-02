import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { SectionTab } from '@/features/shared'

const nav = vi.hoisted(() => ({ pathname: '/attack-surface', push: vi.fn() }))
vi.mock('next/navigation', () => ({
  usePathname: () => nav.pathname,
  useRouter: () => ({ push: nav.push, replace: vi.fn(), prefetch: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}))
// The gate is the tab's own (module, permission); here every tab passed it
// unless the test lists it as hidden.
const gate = vi.hoisted(() => ({ hidden: new Set<string>() }))
vi.mock('@/lib/permissions', () => ({
  useVisibleSectionTabs: (tabs: readonly SectionTab[]) =>
    tabs.filter((t) => !gate.hidden.has(t.href)),
}))

const { AttackSurfaceNav } = await import('../attack-surface-nav')

const TABS: SectionTab[] = [
  { label: 'Overview', href: '/attack-surface' },
  { label: 'Review', href: '/attack-surface/review' },
  { label: 'Lookalikes', href: '/attack-surface/lookalikes' },
  { label: 'Changes', href: '/attack-surface/changes' },
  { label: 'Web surface', href: '/attack-surface/web' },
  { label: 'Technologies', href: '/attack-surface/technologies' },
  { label: 'Certificates', href: '/attack-surface/certificates' },
]

function strip() {
  return screen.getByRole('navigation', { name: 'Attack surface sections' })
}

beforeEach(() => {
  nav.pathname = '/attack-surface'
  nav.push.mockReset()
  gate.hidden = new Set()
})

describe('AttackSurfaceNav', () => {
  it('shows the five views, not one tab per route', () => {
    render(<AttackSurfaceNav tabs={TABS} label="Attack surface sections" />)
    const links = within(strip()).getAllByRole('link')
    expect(links.map((a) => a.textContent?.trim())).toEqual([
      'Overview',
      'Inventory',
      'Exposures',
      'Changes',
      'Discovery',
    ])
    // A view opens its first route the user can see.
    expect(links.map((a) => a.getAttribute('href'))).toEqual([
      '/attack-surface',
      '/attack-surface/technologies',
      '/attack-surface/lookalikes',
      '/attack-surface/changes',
      '/attack-surface/review',
    ])
  })

  it('marks the view of a nested route active and shows its lens', async () => {
    nav.pathname = '/attack-surface/certificates'
    render(<AttackSurfaceNav tabs={TABS} label="Attack surface sections" />)
    expect(within(strip()).getByRole('link', { name: 'Inventory' })).toHaveAttribute(
      'aria-current',
      'page'
    )
    const lens = screen.getByRole('radiogroup', { name: 'Inventory views' })
    const options = within(lens).getAllByRole('radio')
    expect(options.map((o) => o.textContent)).toEqual([
      'Technologies',
      'Certificates',
      'Web surface',
    ])
    expect(within(lens).getByRole('radio', { name: 'Certificates' })).toHaveAttribute(
      'aria-checked',
      'true'
    )
    await userEvent.click(within(lens).getByRole('radio', { name: 'Web surface' }))
    expect(nav.push).toHaveBeenCalledWith('/attack-surface/web')
  })

  it('draws no lens for a view with one route', () => {
    nav.pathname = '/attack-surface'
    render(<AttackSurfaceNav tabs={TABS} label="Attack surface sections" />)
    expect(screen.queryByRole('radiogroup')).toBeNull()
  })

  it('names the Discovery routes by what they hold and counts the waiting decisions', () => {
    nav.pathname = '/attack-surface/review'
    render(
      <AttackSurfaceNav
        tabs={[...TABS, { label: 'Discovery', href: '/attack-surface/discovery' }]}
        label="Attack surface sections"
        counts={{ '/attack-surface/review': 4 }}
      />
    )
    const lens = screen.getByRole('radiogroup', { name: 'Discovery views' })
    expect(
      within(lens)
        .getAllByRole('radio')
        .map((o) => o.textContent)
    ).toEqual(['Stages', 'Decisions4'])
    expect(within(strip()).getByRole('link', { name: /Discovery/ }).textContent).toContain('4')
  })

  it('hides a view whose routes the user cannot open', () => {
    gate.hidden = new Set([
      '/attack-surface/web',
      '/attack-surface/technologies',
      '/attack-surface/certificates',
    ])
    render(<AttackSurfaceNav tabs={TABS} label="Attack surface sections" />)
    expect(within(strip()).queryByRole('link', { name: 'Inventory' })).toBeNull()
  })

  it('draws nothing when only one view is left', () => {
    render(<AttackSurfaceNav tabs={[{ label: 'Overview', href: '/attack-surface' }]} label="x" />)
    expect(screen.queryByRole('navigation')).toBeNull()
  })
})
