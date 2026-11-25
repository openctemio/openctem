import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

// cmdk measures its list; jsdom has neither of these.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= vi.fn()

const push = vi.fn()
let pathname = '/'
vi.mock('next/navigation', () => ({ useRouter: () => ({ push }), usePathname: () => pathname }))
vi.mock('next-themes', () => ({ useTheme: () => ({ setTheme: vi.fn() }) }))
vi.mock('@/context/search-provider', () => ({
  useSearch: () => ({ open: true, setOpen: vi.fn() }),
}))
vi.mock('@/context/brand-provider', async (orig) => ({
  ...(await orig<typeof import('@/context/brand-provider')>()),
  useDocsHref: () => (u: string) => u,
}))
vi.mock('@/lib/permissions/hooks', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions/hooks')>()),
  usePermissions: () => ({ permissions: [], tenantRole: 'member' }),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useFilteredSidebarData: () => ({
    data: { navGroups: [{ title: 'Overview', items: sidebarItems }] },
  }),
}))
vi.mock('@/hooks/use-settings-nav', () => ({ useSettingsNav: () => [] }))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => true,
}))
let perms = new Set<string>()
let sidebarItems: { title: string; url: string }[] = [{ title: 'Dashboard', url: '/' }]
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => perms.has(p) }),
}))
vi.mock('@/features/findings/api/use-quick-views', () => ({
  useFindingQuickViews: () => ({ data: undefined }),
}))
vi.mock('@/features/saved-views/api/use-saved-views', () => ({
  useSavedViews: () => ({ views: [] }),
}))
const searchState = { results: [] as unknown[], loading: false, cve: null as string | null }
vi.mock('@/features/command-palette/use-palette-search', () => ({
  usePaletteSearch: () => searchState,
}))

import { CommandMenu } from '../command-menu'
import { recordRecentPage } from '@/features/command-palette/recent-pages'

beforeEach(() => {
  push.mockReset()
  searchState.results = []
  searchState.cve = null
  sidebarItems = [{ title: 'Dashboard', url: '/' }]
  pathname = '/'
  window.localStorage.clear()
})

describe('CommandMenu', () => {
  it('offers only the open-a-form commands the caller may use', () => {
    perms = new Set(['scans:write'])
    render(<CommandMenu />)
    expect(screen.getByText('New scan')).toBeTruthy()
    expect(screen.queryByText('Import results')).toBeNull()
    expect(screen.queryByText('Create remediation task')).toBeNull()
  })

  it('a command opens the page with its form, never writes', () => {
    perms = new Set(['scans:write'])
    render(<CommandMenu />)
    fireEvent.click(screen.getByText('New scan'))
    expect(push).toHaveBeenCalledWith('/scans?new=scan')
  })

  it('> lists commands only', () => {
    perms = new Set(['scans:write', 'findings:read'])
    render(<CommandMenu />)
    expect(screen.getByText('Dashboard')).toBeTruthy()
    fireEvent.change(screen.getByRole('combobox'), { target: { value: '>' } })
    expect(screen.queryByText('Dashboard')).toBeNull()
    expect(screen.getByText('New scan')).toBeTruthy()
  })

  it('shows entity results and a CVE shortcut', () => {
    perms = new Set(['findings:read'])
    searchState.results = [
      { kind: 'finding', id: 'f1', label: 'SQL injection in login', href: '/findings/f1' },
      { kind: 'asset', id: 'a1', label: 'proxy-edge-01', href: '/assets/a1' },
    ]
    searchState.cve = 'CVE-2026-41187'
    render(<CommandMenu />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'CVE-2026-41187' } })
    expect(screen.getByText('SQL injection in login')).toBeTruthy()
    expect(screen.getByText('proxy-edge-01')).toBeTruthy()
    fireEvent.click(screen.getByText('Findings for CVE-2026-41187'))
    expect(push).toHaveBeenCalledWith('/findings?cve_id=CVE-2026-41187')
  })

  it('a typed CVE under Vulnerability opens the vulnerability page, findings stay second', () => {
    perms = new Set(['findings:read'])
    sidebarItems = [{ title: 'Vulnerabilities', url: '/vulnerabilities' }]
    searchState.cve = 'CVE-2026-41187'
    render(<CommandMenu />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'CVE-2026-41187' } })
    fireEvent.click(screen.getByText('Open CVE-2026-41187'))
    expect(push).toHaveBeenCalledWith('/vulnerabilities/CVE-2026-41187')
    expect(screen.getByText('Findings for CVE-2026-41187')).toBeTruthy()
  })

  it('offers no vulnerability page link when the sidebar does not', () => {
    perms = new Set(['findings:read'])
    searchState.cve = 'CVE-2026-41187'
    render(<CommandMenu />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'CVE-2026-41187' } })
    expect(screen.queryByText('Open CVE-2026-41187')).toBeNull()
  })

  it('an empty search shows Recent, Go to and Create, and keeps the full index for typing', () => {
    perms = new Set(['scans:write'])
    sidebarItems = [
      { title: 'Dashboard', url: '/' },
      { title: 'Findings', url: '/findings' },
      { title: 'Assets', url: '/assets' },
      { title: 'Audit log', url: '/audit' },
    ]
    recordRecentPage('/audit')
    recordRecentPage('/assets')
    render(<CommandMenu />)
    const headings = [...document.querySelectorAll('[cmdk-group-heading]')].map(
      (h) => h.textContent
    )
    expect(headings).toEqual(['Recent', 'Go to', 'Create'])
    // Assets is recent, so Go to does not repeat it; Audit log is not a main section.
    expect(screen.getAllByText('Assets')).toHaveLength(1)
    expect(screen.getByText('Audit log')).toBeTruthy()
    expect(screen.queryByText('Light theme')).toBeNull()
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'theme' } })
    expect(screen.getByText('Light theme')).toBeTruthy()
    expect(screen.queryByText('Recent')).toBeNull()
  })

  it('Recent never offers a page the caller can no longer open, nor the page they are on', () => {
    perms = new Set()
    sidebarItems = [
      { title: 'Dashboard', url: '/' },
      { title: 'Findings', url: '/findings' },
    ]
    pathname = '/findings'
    recordRecentPage('/sensors')
    recordRecentPage('/findings')
    render(<CommandMenu />)
    expect(screen.queryByText('Recent')).toBeNull()
    expect(screen.queryByText('Sensors')).toBeNull()
  })

  it('a recent page opens on select', () => {
    perms = new Set()
    sidebarItems = [{ title: 'Findings', url: '/findings' }]
    recordRecentPage('/findings')
    render(<CommandMenu />)
    fireEvent.click(screen.getByText('Findings'))
    expect(push).toHaveBeenCalledWith('/findings')
  })

  it('each create command has its own icon, not one shared plus', () => {
    perms = new Set(['scans:write', 'assets:write', 'findings:write'])
    render(<CommandMenu />)
    const icons = ['New scan', 'Add asset', 'New finding'].map(
      (label) =>
        screen
          .getByText(label)
          .closest('[cmdk-item]')
          ?.querySelector('svg')
          ?.getAttribute('class') ?? ''
    )
    expect(new Set(icons).size).toBe(3)
    expect(icons.some((c) => c.includes('lucide-plus'))).toBe(false)
  })

  it('closes from the search row (Esc key cap, Close on a phone) and shows key hints', () => {
    perms = new Set()
    render(<CommandMenu />)
    expect(screen.getByRole('button', { name: /^Esc ?Close$/ })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Close' })).toBeTruthy()
    const footer = document.querySelector('[data-slot="command-footer"]')
    expect(footer?.textContent).toContain('Move')
    expect(footer?.textContent).toContain('Open')
    expect(footer?.textContent).toContain('Close')
    expect(
      screen.getByPlaceholderText('Search pages, findings, assets… or type > for commands')
    ).toBeTruthy()
  })
})
