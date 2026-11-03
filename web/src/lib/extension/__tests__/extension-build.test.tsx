/**
 * Contract test of the web extension points with a fake overlay: what an
 * extension registers reaches the sidebar, the settings navigation and the
 * slots, gated like core entries, and nothing else changes. Runs in the
 * public repository, so a core change that breaks the contract fails here.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { FileText } from 'lucide-react'

vi.mock('@extension/web', () => ({
  extension: {
    apiVersion: 1,
    edition: 'test-edition',
    navItems: [
      {
        group: 'Validation',
        item: {
          title: 'Fake page',
          url: '/fake-page',
          module: 'fake_module',
          permission: 'fake:read',
        },
      },
    ],
    settingsItems: [
      {
        group: 'organization',
        item: {
          id: 'fake-settings',
          title: 'Fake settings',
          description: 'A page the fake overlay adds.',
          url: '/settings/fake',
          icon: FileText,
          permission: 'fake:write',
          module: 'fake_module',
        },
      },
    ],
    slots: {
      'reports.sections': () => <p>fake section</p>,
      'settings.scim.sections': () => <p>fake scim section</p>,
    },
    overrides: {
      'auth.footer': ({ className }: { className?: string }) => (
        <p className={className}>fake footer</p>
      ),
    },
  },
}))

describe('extension build (fake overlay)', () => {
  it('adds the overlay rows to the sidebar group it names, keeping their gates', async () => {
    const { sidebarData } = await import('@/config/sidebar-data')
    const group = sidebarData.navGroups.find((g) => g.title === 'Validation')
    const row = group?.items.find((i) => 'url' in i && i.url === '/fake-page')
    expect(row).toMatchObject({ module: 'fake_module', permission: 'fake:read' })
  })

  it('adds the overlay settings page to its group', async () => {
    const { settingsNav, settingsNavItems } = await import('@/config/settings-nav')
    const org = settingsNav.find((g) => g.id === 'organization')
    expect(org?.items.at(-1)).toMatchObject({ id: 'fake-settings', permission: 'fake:write' })
    expect(settingsNavItems.some((i) => i.id === 'fake-settings')).toBe(true)
  })

  it('renders the overlay component in its slot', async () => {
    const { ExtensionSlot } = await import('@/lib/extension/slot')
    render(<ExtensionSlot id="reports.sections" />)
    expect(screen.getByText('fake section')).toBeInTheDocument()
  })

  it('renders each slot only where its id is used', async () => {
    const { ExtensionSlot } = await import('@/lib/extension/slot')
    render(<ExtensionSlot id="settings.scim.sections" />)
    expect(screen.getByText('fake scim section')).toBeInTheDocument()
    expect(screen.queryByText('fake section')).not.toBeInTheDocument()
  })

  it('replaces an overridable core component and passes its props', async () => {
    const { Overridable } = await import('@/lib/extension/overridable')
    const Core = () => <p>core footer</p>
    render(<Overridable id="auth.footer" fallback={Core} className="pt-4" />)
    expect(screen.getByText('fake footer')).toHaveClass('pt-4')
    expect(screen.queryByText('core footer')).not.toBeInTheDocument()
  })
})
