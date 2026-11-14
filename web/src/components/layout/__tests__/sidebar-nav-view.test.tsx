import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { usePathname } from 'next/navigation'
import { Home, User } from 'lucide-react'
import { Sidebar, SidebarContent, SidebarProvider, SidebarTrigger } from '@/components/ui/sidebar'
import { GroupedNav } from '../grouped-nav'
import { SettingsSidebarNav } from '../settings-sidebar-nav'
import { SidebarFooterLinks } from '../sidebar-footer-links'
import { SidebarNavViewProvider, SidebarNavViews, useSidebarNavView } from '../sidebar-nav-view'

// The width decides drawer (phone) or rail (desktop).
const viewport = vi.hoisted(() => ({ mobile: true }))
vi.mock('@/hooks/use-mobile', async (orig) => ({
  ...(await orig<typeof import('@/hooks/use-mobile')>()),
  useIsMobile: () => viewport.mobile,
}))

// The settings rail's groups come from permissions and modules; one group here.
vi.mock('@/hooks/use-settings-nav', () => ({
  useSettingsNav: () => [
    {
      id: 'account',
      label: 'My account',
      items: [{ id: 'profile', label: 'Profile', url: '/account/profile', icon: User }],
    },
  ],
  settingsSections: (items: unknown[]) => [{ items }],
}))

vi.mock('@/hooks/use-build-versions', () => ({
  useBuildVersions: () => ({ web: undefined, api: undefined }),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

// The set the provider reports, readable while the drawer is closed too.
function Probe() {
  return <output data-testid="nav-view">{useSidebarNavView().view}</output>
}

function Shell() {
  return (
    <SidebarProvider>
      <SidebarTrigger />
      <SidebarNavViewProvider>
        <Probe />
        <Sidebar collapsible="icon">
          <SidebarContent>
            <SidebarNavViews
              views={{
                app: (
                  <GroupedNav
                    sections={[
                      {
                        key: 'main',
                        items: [
                          { key: 'findings', title: 'Findings', url: '/findings', icon: Home },
                        ],
                      },
                    ]}
                  />
                ),
                settings: <SettingsSidebarNav />,
              }}
            />
          </SidebarContent>
          <SidebarFooterLinks shell="app" showSettings />
        </Sidebar>
      </SidebarNavViewProvider>
    </SidebarProvider>
  )
}

const drawer = () => document.querySelector<HTMLElement>('[data-mobile="true"]')
const navView = () => screen.getByTestId('nav-view').textContent

async function openDrawer(user: ReturnType<typeof userEvent.setup>) {
  // hidden: while the modal drawer is up, the page behind is aria-hidden.
  await user.click(screen.getByRole('button', { name: /open sidebar/i, hidden: true }))
  expect(drawer()).toBeTruthy()
}

// Keep links from navigating jsdom; the route is driven by usePathname.
function stopNavigation() {
  const stop = (e: Event) => e.preventDefault()
  document.addEventListener('click', stop)
  return () => document.removeEventListener('click', stop)
}

describe('sidebar navigation sets', () => {
  beforeEach(() => {
    viewport.mobile = true
  })

  describe('on a phone (drawer)', () => {
    it('Back to app shows the app navigation and keeps the drawer open', async () => {
      vi.mocked(usePathname).mockReturnValue('/account/profile')
      const user = userEvent.setup()
      render(<Shell />)
      await openDrawer(user)
      expect(navView()).toBe('settings')

      const back = within(drawer()!).getByRole('button', { name: 'Back to app' })
      // A switch, not a link: it does not leave the page.
      expect(back.closest('a')).toBeNull()
      await user.click(back)

      expect(drawer()).toBeTruthy()
      expect(navView()).toBe('app')
      expect(within(drawer()!).getByRole('link', { name: 'Findings' })).toBeInTheDocument()
      // Focus moves to the first row of the new set, inside the drawer.
      expect(document.activeElement).toBe(within(drawer()!).getByRole('link', { name: 'Findings' }))
    })

    it('Settings shows the settings rail and keeps the drawer open', async () => {
      vi.mocked(usePathname).mockReturnValue('/findings')
      const user = userEvent.setup()
      render(<Shell />)
      await openDrawer(user)
      expect(navView()).toBe('app')

      await user.click(within(drawer()!).getByRole('button', { name: 'Settings' }))

      expect(drawer()).toBeTruthy()
      expect(navView()).toBe('settings')
      expect(document.activeElement).toBe(
        within(drawer()!).getByRole('button', { name: 'Back to app' })
      )
      // And back again, still open.
      await user.click(within(drawer()!).getByRole('button', { name: 'Back to app' }))
      expect(drawer()).toBeTruthy()
      expect(navView()).toBe('app')
    })

    it('picking a page closes the drawer, without flashing the other set', async () => {
      vi.mocked(usePathname).mockReturnValue('/account/profile')
      const restore = stopNavigation()
      const user = userEvent.setup()
      render(<Shell />)
      await openDrawer(user)
      await user.click(within(drawer()!).getByRole('button', { name: 'Back to app' }))

      const findings = within(drawer()!).getByRole('link', { name: 'Findings' })
      await user.click(findings)
      restore()
      expect(drawer()?.getAttribute('data-state') ?? 'closed').toBe('closed')
      // Closing does not switch back: the drawer slides out (0.2s) on the set
      // that was picked, and the page's own set comes with the navigation.
      expect(navView()).toBe('app')
    })

    it('a navigation (picked row or browser back) hands the set back to the route', async () => {
      vi.mocked(usePathname).mockReturnValue('/account/profile')
      const user = userEvent.setup()
      const { rerender } = render(<Shell />)
      await openDrawer(user)
      await user.click(within(drawer()!).getByRole('button', { name: 'Back to app' }))
      expect(navView()).toBe('app')

      // Browser back to another settings page, drawer still open.
      vi.mocked(usePathname).mockReturnValue('/account/security')
      rerender(<Shell />)
      expect(navView()).toBe('settings')
    })

    it('a drawer that opens again starts on the page’s own set', async () => {
      vi.mocked(usePathname).mockReturnValue('/account/profile')
      const user = userEvent.setup()
      render(<Shell />)
      await openDrawer(user)
      await user.click(within(drawer()!).getByRole('button', { name: 'Back to app' }))
      expect(navView()).toBe('app')

      // The focused row's tooltip layer takes the first Escape, the drawer the next.
      await user.keyboard('{Escape}{Escape}')
      expect(drawer()?.getAttribute('data-state') ?? 'closed').toBe('closed')
      // Not reset under the closing animation...
      expect(navView()).toBe('app')
      // ...but on the next opening.
      await act(async () => {})
      await openDrawer(user)
      expect(navView()).toBe('settings')
    })

    it('Settings is the overview link when the settings rail is already shown', async () => {
      vi.mocked(usePathname).mockReturnValue('/account/profile')
      const user = userEvent.setup()
      render(<Shell />)
      await openDrawer(user)
      expect(within(drawer()!).getByRole('link', { name: 'Settings' })).toHaveAttribute(
        'href',
        '/settings'
      )
    })
  })

  describe('on desktop (rail)', () => {
    it('Back to app is the link to the last app page, and Settings the overview link', () => {
      viewport.mobile = false
      vi.mocked(usePathname).mockReturnValue('/account/profile')
      render(<Shell />)
      expect(navView()).toBe('settings')
      expect(screen.getByRole('link', { name: 'Back to app' })).toHaveAttribute('href', '/')
      expect(screen.getByRole('link', { name: 'Settings' })).toHaveAttribute('href', '/settings')
    })

    it('shows the app navigation on app routes', () => {
      viewport.mobile = false
      vi.mocked(usePathname).mockReturnValue('/findings')
      render(<Shell />)
      expect(navView()).toBe('app')
      expect(screen.getByRole('link', { name: 'Findings' })).toBeInTheDocument()
    })
  })
})
