import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('@/hooks/use-mobile', async (orig) => ({
  ...(await orig<typeof import('@/hooks/use-mobile')>()),
  useIsMobile: () => false,
}))

// Radix tooltips measure with ResizeObserver, which jsdom does not have.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

import { SidebarProvider, useSidebar } from '@/components/ui/sidebar'
import { TooltipProvider } from '@/components/ui/tooltip'
import { SidebarBrand, SIDEBAR_TRAILING_SLOT_CLASS } from '../sidebar-brand'

function State() {
  const { state } = useSidebar()
  return <span data-testid="state">{state}</span>
}

function renderCollapsed() {
  return render(
    <TooltipProvider>
      <SidebarProvider defaultOpen={false}>
        <SidebarBrand />
        <State />
      </SidebarProvider>
    </TooltipProvider>
  )
}

describe('SidebarBrand, collapsed', () => {
  it('shows the mark, and the expand icon on hover or keyboard focus', () => {
    const { container } = renderCollapsed()
    const button = screen.getByRole('button', { name: 'Expand sidebar' })
    const mark = container.querySelector('[data-slot="brand-mark"]')
    const expand = container.querySelector('[data-slot="brand-expand"]')
    expect(mark).not.toBeNull()
    expect(expand).not.toBeNull()
    // The swap is CSS: the icon is hidden at rest and shown on the button's
    // hover / focus-visible; the mark does the opposite.
    expect(expand?.getAttribute('class')).toContain('opacity-0')
    expect(expand?.getAttribute('class')).toContain('group-hover/brand:opacity-100')
    expect(expand?.getAttribute('class')).toContain('group-focus-visible/brand:opacity-100')
    expect(mark?.getAttribute('class')).toContain('group-hover/brand:opacity-0')
    expect(button.className).toContain('group/brand')
    // Both are decorative; the button's label names the action.
    expect(mark?.getAttribute('aria-hidden')).toBe('true')
    expect(expand?.getAttribute('aria-hidden')).toBe('true')
  })

  it('expands the sidebar when clicked', async () => {
    renderCollapsed()
    expect(screen.getByTestId('state').textContent).toBe('collapsed')
    await userEvent.click(screen.getByRole('button', { name: 'Expand sidebar' }))
    expect(screen.getByTestId('state').textContent).toBe('expanded')
  })

  it('names the shortcut in the tooltip', async () => {
    renderCollapsed()
    await userEvent.hover(screen.getByRole('button', { name: 'Expand sidebar' }))
    const tip = await screen.findAllByText('B')
    expect(tip.length).toBeGreaterThan(0)
  })
})

describe('SidebarBrand, expanded', () => {
  it('names the home link by the brand (its lockup is a picture)', () => {
    render(
      <TooltipProvider>
        <SidebarProvider defaultOpen>
          <SidebarBrand />
        </SidebarProvider>
      </TooltipProvider>
    )
    const link = screen.getByRole('link', { name: 'OpenCTEM home' })
    expect(link).toHaveAttribute('href', '/')
    expect(link.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true')
  })

  it('ends the collapse button at the row edge, the same slot as the organization chevron', () => {
    const { container } = render(
      <TooltipProvider>
        <SidebarProvider defaultOpen>
          <SidebarBrand />
        </SidebarProvider>
      </TooltipProvider>
    )
    const row = container.querySelector('[data-slot="sidebar-brand-row"]')!
    expect(row.className).toContain('pe-0')
    // The button is the same width as the chevron's slot (both `control`).
    const trigger = container.querySelector('[data-sidebar="trigger"]')!
    expect(trigger.className).toContain('size-control')
    expect(trigger.className).toContain('max-md:size-control-touch')
    expect(SIDEBAR_TRAILING_SLOT_CLASS).toContain('w-control')
    expect(SIDEBAR_TRAILING_SLOT_CLASS).toContain('max-md:w-control-touch')
  })
})
