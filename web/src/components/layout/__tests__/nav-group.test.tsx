/**
 * Section headers in the main sidebar only fold and unfold. A section with an
 * overview page (Scoping, Validation) used to render its header label as a link
 * to that page, so expanding Scoping also navigated to /scoping. The overview
 * is the section's own "Overview" row instead.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { usePathname } from 'next/navigation'
import { SidebarProvider } from '@/components/ui/sidebar'
import { sidebarData } from '@/config/sidebar-data'
import { NavGroup } from '../nav-group'

vi.mock('@/hooks/use-dynamic-badges', () => ({
  useDynamicBadges: () => ({}),
  getBadgeValue: () => undefined,
}))

vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ subModules: {} }),
}))

// Radix menus measure their trigger; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const group = (title: string) => sidebarData.navGroups.find((g) => g.title === title)!

function renderSection(title: string) {
  const g = group(title)
  return render(
    <SidebarProvider defaultOpen>
      <NavGroup {...g} />
    </SidebarProvider>
  )
}

describe('NavSection header', () => {
  beforeEach(() => {
    vi.mocked(usePathname).mockReturnValue('/findings')
  })

  it.each(['Scoping', 'Validation', 'Discovery'])(
    '%s: the header is a toggle button, never a link',
    async (title) => {
      // Precondition for the url sections: they do have an overview url.
      if (title !== 'Discovery') expect(group(title).url).toBeTruthy()
      renderSection(title)

      expect(screen.queryByRole('link', { name: title })).toBeNull()
      const header = screen.getByRole('button', { name: title })
      expect(header.tagName).toBe('BUTTON')
      expect(header).not.toHaveAttribute('href')
      expect(header.closest('a')).toBeNull()

      const contentId = header.getAttribute('aria-controls')
      expect(contentId).toBeTruthy()
      const content = document.getElementById(contentId!)!
      expect(header).toHaveAttribute('aria-expanded', 'false')
      expect(content).toHaveAttribute('inert')

      await userEvent.click(header)
      expect(header).toHaveAttribute('aria-expanded', 'true')
      expect(content).not.toHaveAttribute('inert')

      await userEvent.click(header)
      expect(header).toHaveAttribute('aria-expanded', 'false')
      expect(content).toHaveAttribute('inert')
    }
  )

  it('has no separate chevron-only toggle (one control per header)', () => {
    renderSection('Scoping')
    expect(screen.queryByRole('button', { name: /^(Expand|Collapse) Scoping$/ })).toBeNull()
  })

  it('keeps the overview one click away via the Overview row', async () => {
    renderSection('Scoping')
    await userEvent.click(screen.getByRole('button', { name: 'Scoping' }))
    const content = document.getElementById(
      screen.getByRole('button', { name: 'Scoping' }).getAttribute('aria-controls')!
    )!
    expect(within(content).getByRole('link', { name: /Overview/ })).toHaveAttribute(
      'href',
      '/scoping'
    )
  })

  it('auto-opens when the section owns the current route', () => {
    vi.mocked(usePathname).mockReturnValue('/scoping')
    renderSection('Scoping')
    const header = screen.getByRole('button', { name: 'Scoping' })
    expect(header).toHaveAttribute('aria-expanded', 'true')
    expect(header).toHaveAttribute('data-current', 'true')
  })
})
