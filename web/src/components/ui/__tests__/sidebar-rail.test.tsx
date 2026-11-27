import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

// 768-1023 px: the docked sidebar is the icon rail, and it opens as a sheet.
const viewport = vi.hoisted(() => ({ tablet: true }))
vi.mock('@/hooks/use-mobile', async (orig) => ({
  ...(await orig<typeof import('@/hooks/use-mobile')>()),
  useIsMobile: () => false,
  useIsTablet: () => viewport.tablet,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

import { Sidebar, SidebarProvider, useSidebar, useSidebarActions } from '../sidebar'

function Probe({ id }: { id: string }) {
  const { state } = useSidebar()
  const { toggleSidebar } = useSidebarActions()
  return (
    <button type="button" data-testid={id} onClick={toggleSidebar}>
      {state}
    </button>
  )
}

function renderShell(defaultOpen = true) {
  return render(
    <SidebarProvider defaultOpen={defaultOpen}>
      <Sidebar collapsible="offcanvas">
        <Probe id="inside" />
      </Sidebar>
      <Probe id="outside" />
    </SidebarProvider>
  )
}

describe('Sidebar at 768-1023 px', () => {
  beforeEach(() => {
    viewport.tablet = true
    document.cookie = 'sidebar_state=; max-age=0; path=/'
  })

  it('docks as the icon rail even when the saved choice is expanded', () => {
    const { container } = renderShell(true)
    const docked = container.querySelector('[data-slot="sidebar"][data-state]')
    expect(docked?.getAttribute('data-state')).toBe('collapsed')
    // The rail, never the off-canvas form, whatever the layout setting.
    expect(docked?.getAttribute('data-collapsible')).toBe('icon')
    expect(screen.getByTestId('outside').textContent).toBe('collapsed')
  })

  it('opens the full sidebar as a sheet over the page, expanded inside, and Esc closes it', async () => {
    renderShell(true)
    expect(screen.queryByRole('dialog')).toBeNull()

    await userEvent.click(screen.getByTestId('outside'))
    const sheet = await screen.findByRole('dialog')
    expect(sheet.getAttribute('data-sheet')).toBe('true')
    // Desktop rows in the sheet, not the phone drawer's.
    expect(sheet.getAttribute('data-mobile')).toBeNull()
    // Focus moves into the sheet, but not onto a control with a tooltip.
    expect(document.activeElement).toBe(sheet)
    const inSheet = sheet.querySelector('[data-testid="inside"]')
    expect(inSheet?.textContent).toBe('expanded')
    // The docked rail stays the rail underneath.
    expect(screen.getByTestId('outside').textContent).toBe('collapsed')
    // Opening the sheet does not change the saved expanded/collapsed choice.
    expect(document.cookie).not.toContain('sidebar_state')

    await userEvent.keyboard('{Escape}')
    await act(async () => {})
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('closes the sheet when the window leaves the 768-1023 range', async () => {
    const { rerender } = renderShell(true)
    await userEvent.click(screen.getByTestId('outside'))
    expect(await screen.findByRole('dialog')).toBeTruthy()

    viewport.tablet = false
    rerender(
      <SidebarProvider defaultOpen>
        <Sidebar collapsible="offcanvas">
          <Probe id="inside" />
        </Sidebar>
        <Probe id="outside" />
      </SidebarProvider>
    )
    await act(async () => {})
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.getByTestId('outside').textContent).toBe('expanded')
  })
})
