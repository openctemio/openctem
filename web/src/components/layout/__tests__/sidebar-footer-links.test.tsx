import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { usePathname } from 'next/navigation'
import { SidebarProvider } from '@/components/ui/sidebar'
import { SidebarFooterLinks } from '../sidebar-footer-links'
import { BrandProvider } from '@/context/brand-provider'
import { DEFAULT_BRAND } from '@/lib/brand'
import { DEFAULT_HELP_LINKS, type HelpLinks } from '@/config/help-links'
import { DEFAULT_BUG_URL, DEFAULT_FEEDBACK_URL, DEFAULT_SECURITY_URL } from '@/config/help-links'
import { DOCS_URL } from '@/lib/docs-links'
import { KEYBOARD_SHORTCUTS, shortcutsForShell } from '@/config/keyboard-shortcuts'

// About reads the builds over the network; the dialog's own test covers that.
vi.mock('@/hooks/use-build-versions', () => ({
  useBuildVersions: (shell: string, open: boolean) =>
    open
      ? {
          web: { version: 'v0.8.0-dev', commit: '4d2f4b02', channel: 'dev' },
          api:
            shell === 'app' ? { version: 'v0.8.0-dev', commit: 'a0a14db0', channel: 'dev' } : null,
        }
      : { web: undefined, api: undefined },
}))

// Radix menus measure their trigger; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function renderFooter(props: Parameters<typeof SidebarFooterLinks>[0], defaultOpen = true) {
  return render(
    <SidebarProvider defaultOpen={defaultOpen}>
      <SidebarFooterLinks {...props} />
    </SidebarProvider>
  )
}

const settingsLink = () => screen.getByRole('link', { name: 'Settings' })

describe('SidebarFooterLinks', () => {
  beforeEach(() => {
    vi.mocked(usePathname).mockReturnValue('/findings')
  })

  it('renders Settings and Help as sidebar rows under a separator', () => {
    const { container } = renderFooter({ shell: 'app', showSettings: true })
    const footer = container.querySelector('[data-sidebar="footer"]')!
    expect(footer).toBeTruthy()
    expect(footer.querySelector('[data-slot="separator"], [role="none"], hr')).toBeTruthy()
    expect(settingsLink()).toHaveAttribute('href', '/settings')
    expect(screen.getByRole('button', { name: 'Help' })).toBeInTheDocument()
    // Same row component as the nav (SidebarMenuButton).
    for (const row of [settingsLink(), screen.getByRole('button', { name: 'Help' })]) {
      expect(row).toHaveAttribute('data-sidebar', 'menu-button')
    }
  })

  it.each(['/settings', '/settings/members', '/settings/scanning/profiles/1', '/account/security'])(
    'marks Settings active on %s',
    (path) => {
      vi.mocked(usePathname).mockReturnValue(path)
      renderFooter({ shell: 'app', showSettings: true })
      expect(settingsLink()).toHaveAttribute('data-active', 'true')
    }
  )

  it.each(['/', '/findings', '/scan-profiles-x', '/settingsx'])(
    'does not mark Settings active on %s',
    (path) => {
      vi.mocked(usePathname).mockReturnValue(path)
      renderFooter({ shell: 'app', showSettings: true })
      expect(settingsLink()).toHaveAttribute('data-active', 'false')
    }
  )

  it('keeps both rows (icon + tooltip) on the collapsed rail', () => {
    renderFooter({ shell: 'app', showSettings: true }, false)
    expect(settingsLink().querySelector('svg')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Help' }).querySelector('svg')).toBeTruthy()
  })

  it('the admin console footer has Help but no tenant Settings, plus its own rows', () => {
    render(
      <SidebarProvider>
        <SidebarFooterLinks shell="admin">
          <li>Sign out row</li>
        </SidebarFooterLinks>
      </SidebarProvider>
    )
    expect(screen.queryByRole('link', { name: 'Settings' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Help' })).toBeInTheDocument()
    expect(screen.getByText('Sign out row')).toBeInTheDocument()
  })

  it('Help opens a menu with docs, shortcuts, the three report entries and about', async () => {
    const user = userEvent.setup()
    renderFooter({ shell: 'app', showSettings: true })
    await user.click(screen.getByRole('button', { name: 'Help' }))
    const menu = await screen.findByRole('menu')
    const items = within(menu).getAllByRole('menuitem')
    expect(items.map((i) => i.textContent?.replace('(opens in a new tab)', '').trim())).toEqual([
      'Documentation',
      'Keyboard shortcuts',
      'Report a bug',
      'Send feedback or request a feature',
      'Report a security vulnerability',
      'About OpenCTEM',
    ])

    const docs = within(menu).getByRole('menuitem', { name: /Documentation/ })
    expect(docs).toHaveAttribute('href', DOCS_URL)
    expect(docs).toHaveAttribute('target', '_blank')
    expect(docs.getAttribute('rel')).toContain('noopener')

    for (const [name, href] of [
      [/Report a bug/, DEFAULT_BUG_URL],
      [/Send feedback/, DEFAULT_FEEDBACK_URL],
      [/security vulnerability/, DEFAULT_SECURITY_URL],
    ] as const) {
      const item = within(menu).getByRole('menuitem', { name })
      expect(item).toHaveAttribute('href', href)
      expect(item).toHaveAttribute('target', '_blank')
      expect(item.getAttribute('rel')).toContain('noopener')
    }
    // A vulnerability is never filed as a public issue.
    expect(DEFAULT_SECURITY_URL).not.toContain('/issues')
  })

  it('Keyboard shortcuts lists exactly the configured shortcuts for the shell', async () => {
    const user = userEvent.setup()
    renderFooter({ shell: 'app', showSettings: true })
    await user.click(screen.getByRole('button', { name: 'Help' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Keyboard shortcuts' }))
    const dialog = await screen.findByRole('dialog', { name: 'Keyboard shortcuts' })
    const listed = Array.from(dialog.querySelectorAll('[data-shortcut]')).map((el) =>
      el.getAttribute('data-shortcut')
    )
    expect(listed).toEqual(shortcutsForShell('app').map((s) => s.id))
    expect(listed).toEqual(KEYBOARD_SHORTCUTS.map((s) => s.id))
    expect(within(dialog).getByText('Show or hide the sidebar')).toBeInTheDocument()
  })

  it('the admin console lists only what works there (no palette, no org switch)', async () => {
    const user = userEvent.setup()
    renderFooter({ shell: 'admin' })
    await user.click(screen.getByRole('button', { name: 'Help' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Keyboard shortcuts' }))
    const dialog = await screen.findByRole('dialog', { name: 'Keyboard shortcuts' })
    const listed = Array.from(dialog.querySelectorAll('[data-shortcut]')).map((el) =>
      el.getAttribute('data-shortcut')
    )
    expect(listed).toEqual(['toggle-sidebar'])
  })

  it('About shows the web app and API builds', async () => {
    const user = userEvent.setup()
    renderFooter({ shell: 'app', showSettings: true })
    await user.click(screen.getByRole('button', { name: 'Help' }))
    await user.click(await screen.findByRole('menuitem', { name: 'About OpenCTEM' }))
    const dialog = await screen.findByRole('dialog', { name: 'About OpenCTEM' })
    expect(within(dialog).getByTestId('about-ui-version')).toHaveTextContent('v0.8.0-dev(4d2f4b02)')
    expect(within(dialog).getByTestId('about-ui-version')).toHaveTextContent('Development build')
    expect(within(dialog).getByTestId('about-api-version')).toHaveTextContent(
      'v0.8.0-dev(a0a14db0)'
    )
  })

  it('About in the admin console reads the API with its shell', async () => {
    const user = userEvent.setup()
    renderFooter({ shell: 'admin' })
    await user.click(screen.getByRole('button', { name: 'Help' }))
    await user.click(await screen.findByRole('menuitem', { name: 'About OpenCTEM' }))
    const dialog = await screen.findByRole('dialog', { name: 'About OpenCTEM' })
    expect(within(dialog).getByTestId('about-api-version')).toHaveTextContent('unavailable')
  })
})

describe('SidebarFooterLinks help links set by the operator', () => {
  const help = (over: Partial<HelpLinks>) => ({ ...DEFAULT_HELP_LINKS, ...over })
  const open = async (brandHelp: HelpLinks) => {
    const user = userEvent.setup()
    render(
      <BrandProvider brand={{ ...DEFAULT_BRAND, help: brandHelp }}>
        <SidebarProvider>
          <SidebarFooterLinks shell="app" />
        </SidebarProvider>
      </BrandProvider>
    )
    await user.click(screen.getByRole('button', { name: 'Help' }))
    return within(await screen.findByRole('menu'))
  }

  it('repoints the bug and feedback entries and the security entry', async () => {
    const menu = await open(
      help({
        bugUrl: 'https://jira.corp.example/bug',
        feedbackUrl: 'https://jira.corp.example/idea',
        securityUrl: 'mailto:secops@corp.example',
      })
    )
    expect(menu.getByRole('menuitem', { name: /Report a bug/ })).toHaveAttribute(
      'href',
      'https://jira.corp.example/bug'
    )
    expect(menu.getByRole('menuitem', { name: /Send feedback/ })).toHaveAttribute(
      'href',
      'https://jira.corp.example/idea'
    )
    expect(menu.getByRole('menuitem', { name: /security vulnerability/ })).toHaveAttribute(
      'href',
      'mailto:secops@corp.example'
    )
  })

  it('hides bug and feedback but keeps the security entry', async () => {
    const menu = await open(help({ hidden: true }))
    expect(menu.queryByRole('menuitem', { name: /Report a bug/ })).toBeNull()
    expect(menu.queryByRole('menuitem', { name: /Send feedback/ })).toBeNull()
    expect(menu.getByRole('menuitem', { name: /security vulnerability/ })).toBeInTheDocument()
  })
})
