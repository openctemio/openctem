/**
 * One filled row per sidebar. A pinned page or quick view is also a row of the
 * tree (the page row, the quick view under Findings), which holds the fill, so
 * the pin mirrors the current page unfilled. A pinned saved view has no row of
 * its own and is filled.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { usePathname } from 'next/navigation'
import { SidebarProvider } from '@/components/ui/sidebar'
import { sidebarData } from '@/config/sidebar-data'
import type { NavPin } from '@/features/nav-pins/api/use-nav-pins'
import { NavPinned } from '../nav-pinned'

let pins: NavPin[] = []
let search = ''

vi.mock('@/features/nav-pins/api/use-nav-pins', () => ({
  useNavPins: () => ({
    pins,
    includeInformational: false,
    isPinned: () => true,
    toggle: vi.fn(),
  }),
}))

vi.mock('@/hooks/use-url-param', () => ({
  useUrlParams: () => new URLSearchParams(search),
}))

function renderPins() {
  return render(
    <SidebarProvider defaultOpen>
      <NavPinned groups={sidebarData.navGroups} />
    </SidebarProvider>
  )
}

describe('NavPinned current row', () => {
  beforeEach(() => {
    search = ''
  })

  it('a pinned page on its own page is current but not filled', () => {
    vi.mocked(usePathname).mockReturnValue('/findings')
    pins = [{ kind: 'page', ref: '/findings' }]
    renderPins()
    const link = screen.getByRole('link', { name: /findings/i })
    expect(link).toHaveAttribute('aria-current', 'page')
    expect(link).toHaveAttribute('data-active', 'false')
    expect(link).toHaveAttribute('data-current', 'true')
  })

  it('a pinned saved view on its own list is the filled row', () => {
    vi.mocked(usePathname).mockReturnValue('/findings')
    search = 'view=abc'
    pins = [{ kind: 'saved_view', ref: 'abc', name: 'Night shift' }]
    renderPins()
    const link = screen.getByRole('link', { name: /night shift/i })
    expect(link).toHaveAttribute('data-active', 'true')
    expect(link).not.toHaveAttribute('data-current')
  })

  it('a pin elsewhere is neither filled nor current', () => {
    vi.mocked(usePathname).mockReturnValue('/assets')
    pins = [{ kind: 'page', ref: '/findings' }]
    renderPins()
    const link = screen.getByRole('link', { name: /findings/i })
    expect(link).toHaveAttribute('data-active', 'false')
    expect(link).not.toHaveAttribute('data-current')
  })
})
