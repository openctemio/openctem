import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SidebarProvider } from '@/components/ui/sidebar'
import { ConsoleAccountMenu } from '../components/console-account-menu'
import type { AdminIdentity } from '../types'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const reload = vi.fn()

const admin: AdminIdentity = {
  id: 'a',
  email: 'root@example.test',
  name: 'Root',
  role: 'readonly',
  max_role: 'super_admin',
  roles: ['platform_owner'],
  permissions: ['platform.console.read'],
  max_permissions: ['platform.console.read'],
}

function renderMenu(onSignOut = vi.fn()) {
  render(
    <SidebarProvider>
      <ConsoleAccountMenu admin={admin} onSignOut={onSignOut} />
    </SidebarProvider>
  )
  return onSignOut
}

describe('console account menu', () => {
  beforeEach(() => {
    reload.mockReset()
    document.cookie = 'locale=; path=/; max-age=0'
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...window.location, reload },
    })
  })

  it('is one row named for the administrator, holding keys, language and sign-out', async () => {
    renderMenu()
    const trigger = screen.getByRole('button', { name: 'Account menu for Root' })
    expect(trigger).toHaveTextContent('Root')
    await userEvent.click(trigger)
    expect(await screen.findByText('root@example.test')).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: 'My security keys' })).toHaveAttribute(
      'href',
      '/security/keys'
    )
    expect(screen.getByRole('menuitem', { name: /Language/ })).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: 'Sign out' })).toBeInTheDocument()
  })

  it('signs out from the menu', async () => {
    const onSignOut = renderMenu()
    await userEvent.click(screen.getByRole('button', { name: 'Account menu for Root' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Sign out' }))
    expect(onSignOut).toHaveBeenCalledTimes(1)
  })

  it('sets the locale cookie to the chosen language and reloads', async () => {
    renderMenu()
    await userEvent.click(screen.getByRole('button', { name: 'Account menu for Root' }))
    const language = await screen.findByRole('menuitem', { name: /Language/ })
    language.focus()
    await userEvent.keyboard('{ArrowRight}')
    expect(await screen.findByRole('menuitem', { name: 'English' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('menuitem', { name: 'Tiếng Việt' }))
    expect(document.cookie).toContain('locale=vi')
    expect(reload).toHaveBeenCalled()
  })
})
