import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useRouter } from 'next/navigation'

import { organizationHref } from '@console/features/admin-console/lib/console-links'
import type { AdminOrganization } from '@console/features/admin-console/types'
import AdminOrganizationsPage from '../page'

const state = vi.hoisted(() => ({
  permissions: [] as string[],
  rows: [] as unknown[],
  total: 0,
  error: undefined as unknown,
  queries: [] as Record<string, unknown>[],
}))

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@console/features/admin-console/components/admin-console-shell', () => ({
  useAdmin: () => ({ role: 'readonly', permissions: state.permissions }),
  useAdminOrNull: () => ({ role: 'readonly', permissions: state.permissions }),
}))
vi.mock('@console/features/admin-console/components/create-organization-dialog', () => ({
  CreateOrganizationDialog: () => <button type="button">Create organization</button>,
}))
vi.mock('@console/features/admin-console/api/use-admin-organizations', () => ({
  useOrganizations: (query: Record<string, unknown>) => {
    state.queries.push(query)
    return state.error
      ? { data: undefined, error: state.error, isLoading: false, isValidating: false }
      : {
          data: {
            data: state.rows,
            total: state.total,
            page: 1,
            per_page: 25,
            total_pages: 1,
          },
          error: undefined,
          isLoading: false,
          isValidating: false,
          mutate: vi.fn(),
        }
  },
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function org(patch: Partial<AdminOrganization> = {}): AdminOrganization {
  return {
    id: 'o1',
    name: 'Example Works',
    slug: 'example-works',
    status: 'active',
    owner_domains: ['example.com', 'example.org'],
    owner_count: 2,
    limits_apply: true,
    active_members: 12,
    last_member_sign_in_at: '2026-11-01T00:00:00Z',
    saml_enabled: true,
    active_identity_providers: 0,
    sso_enforced: true,
    created_at: '2026-10-01T00:00:00Z',
    ...patch,
  } as AdminOrganization
}

describe('Console organizations list', () => {
  beforeEach(() => {
    state.permissions = []
    state.rows = [
      org(),
      org({ id: 'o2', name: 'No Owner Ltd', slug: 'no-owner', owner_domains: [], owner_count: 0 }),
    ]
    state.total = 2
    state.error = undefined
    state.queries = []
    window.history.replaceState(null, '', '/organizations')
  })

  it('shows the view name with the count once, and one table named after the page', () => {
    render(<AdminOrganizationsPage />)
    expect(screen.getByRole('heading', { level: 2, name: 'All organizations' })).toBeInTheDocument()
    const counts = document.querySelectorAll('[data-slot="list-count"]')
    expect(counts).toHaveLength(1)
    expect(counts[0].textContent).toContain('2 organizations')
    expect(screen.getByRole('table', { name: 'Organizations' })).toBeInTheDocument()
  })

  it('reads 25 organizations a page with no filter by default', () => {
    render(<AdminOrganizationsPage />)
    expect(state.queries.at(-1)).toEqual({
      search: '',
      owner: '',
      status: '',
      page: 1,
      perPage: 25,
    })
  })

  it('sends the status and owner filters of the link', () => {
    window.history.replaceState(null, '', '/organizations?status=suspended&owner=none')
    render(<AdminOrganizationsPage />)
    expect(state.queries.at(-1)).toMatchObject({ status: 'suspended', owner: 'none' })
  })

  it('keeps the columns of the list, each with a label', () => {
    render(<AdminOrganizationsPage />)
    expect(screen.getAllByRole('columnheader').map((h) => h.textContent)).toEqual([
      'Organization',
      'Owner',
      'Limits',
      'Status',
      'Members',
      'Last member sign-in',
      'Single sign-on',
      'Created',
    ])
  })

  it('keeps every fact of a row: slug, owner domains, limits, status, sign-on', () => {
    render(<AdminOrganizationsPage />)
    const row = screen.getByRole('link', { name: 'Example Works' }).closest('tr')!
    expect(within(row).getByText('example-works')).toBeInTheDocument()
    expect(within(row).getByText('example.com')).toBeInTheDocument()
    expect(within(row).getByText('+1')).toBeInTheDocument()
    expect(within(row).getByText('Limited')).toBeInTheDocument()
    expect(within(row).getByText('Active')).toBeInTheDocument()
    expect(within(row).getByText('SAML')).toBeInTheDocument()
    expect(within(row).getByText('Enforced')).toBeInTheDocument()
    const bare = screen.getByRole('link', { name: 'No Owner Ltd' }).closest('tr')!
    expect(within(bare).getByText('No owner')).toBeInTheDocument()
  })

  it('links each organization to its page, the id as one encoded path segment', async () => {
    const push = vi.fn()
    vi.mocked(useRouter).mockReturnValue({ push } as unknown as ReturnType<typeof useRouter>)
    render(<AdminOrganizationsPage />)
    const link = screen.getByRole('link', { name: 'Example Works' })
    expect(link).toHaveAttribute('href', '/organizations/o1')
    await userEvent.click(link)
    expect(push).toHaveBeenCalledWith('/organizations/o1')
    expect(push).toHaveBeenCalledTimes(1)
    expect(organizationHref('../users?x=1#y')).toBe('/organizations/..%2Fusers%3Fx%3D1%23y')
  })

  it('offers Create organization only with the permission to create one', () => {
    const { unmount } = render(<AdminOrganizationsPage />)
    expect(screen.queryByRole('button', { name: 'Create organization' })).not.toBeInTheDocument()
    unmount()
    state.permissions = ['platform.tenants.create']
    render(<AdminOrganizationsPage />)
    expect(screen.getByRole('button', { name: 'Create organization' })).toBeInTheDocument()
  })

  it('has no selection and no row action', () => {
    render(<AdminOrganizationsPage />)
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /row actions/i })).not.toBeInTheDocument()
  })

  it('tells an empty installation from a filter with no match', () => {
    state.rows = []
    state.total = 0
    const { unmount } = render(<AdminOrganizationsPage />)
    expect(screen.getByText('No organizations yet')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Clear filters' })).not.toBeInTheDocument()
    unmount()
    window.history.replaceState(null, '', '/organizations?status=suspended')
    render(<AdminOrganizationsPage />)
    expect(screen.getByText('No organization matches these filters')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Clear filters' })).toBeInTheDocument()
  })

  it('shows the load error in the table, with the toolbar still there', () => {
    state.error = new Error('boom')
    render(<AdminOrganizationsPage />)
    expect(screen.getByRole('button', { name: /Retry|Try again/ })).toBeInTheDocument()
    expect(screen.getByRole('searchbox', { name: 'Search organizations' })).toBeInTheDocument()
  })
})
