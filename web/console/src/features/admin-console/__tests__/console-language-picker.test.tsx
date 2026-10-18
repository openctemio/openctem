import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SidebarProvider } from '@/components/ui/sidebar'
import { ConsoleLanguagePicker } from '../components/console-language-picker'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const reload = vi.fn()

describe('console language picker', () => {
  beforeEach(() => {
    reload.mockReset()
    document.cookie = 'locale=; path=/; max-age=0'
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...window.location, reload },
    })
  })

  it('sets the locale cookie to the chosen language and reloads', async () => {
    render(
      <SidebarProvider>
        <ConsoleLanguagePicker />
      </SidebarProvider>
    )
    await userEvent.click(screen.getByRole('button', { name: /Language/ }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Tiếng Việt' }))
    expect(document.cookie).toContain('locale=vi')
    expect(reload).toHaveBeenCalled()
  })

  it('lists English and Vietnamese by their own names', async () => {
    render(
      <SidebarProvider>
        <ConsoleLanguagePicker />
      </SidebarProvider>
    )
    await userEvent.click(screen.getByRole('button', { name: /Language/ }))
    expect(await screen.findByRole('menuitem', { name: 'English' })).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: 'Tiếng Việt' })).toBeInTheDocument()
  })
})
