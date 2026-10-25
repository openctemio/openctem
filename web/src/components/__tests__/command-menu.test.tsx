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
vi.mock('next/navigation', () => ({ useRouter: () => ({ push }) }))
vi.mock('next-themes', () => ({ useTheme: () => ({ setTheme: vi.fn() }) }))
vi.mock('@/context/search-provider', () => ({
  useSearch: () => ({ open: true, setOpen: vi.fn() }),
}))
vi.mock('@/context/brand-provider', () => ({ useDocsHref: () => (u: string) => u }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useFilteredSidebarData: () => ({
    data: { navGroups: [{ title: 'Overview', items: [{ title: 'Dashboard', url: '/' }] }] },
  }),
}))
vi.mock('@/hooks/use-settings-nav', () => ({ useSettingsNav: () => [] }))
let perms = new Set<string>()
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

beforeEach(() => {
  push.mockReset()
  searchState.results = []
  searchState.cve = null
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
})
