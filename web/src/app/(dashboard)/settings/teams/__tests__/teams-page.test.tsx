/**
 * Teams and assignment rules (board P4-Settings-Teams): one page frame with
 * the tabs; Add filter narrows teams by kind and rules by status through the
 * URL and shows a chip; delete names the members and assets a team affects;
 * a reader without the create permission is told the page is view only; a
 * failed read shows Retry instead of an empty list; the condition choices of
 * a new rule are toggle buttons a keyboard can reach.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { I18nProvider } from '@/context/i18n-provider'
import type { Group } from '@/features/access-control'
import TeamsPage from '../page'

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', slug: 'acme', role: 'owner' } }),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: ReactNode }) => <main>{children}</main>,
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/settings/teams',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))

let canMutate = true
vi.mock('@/lib/permissions', async (orig) => {
  const mod = await orig<typeof import('@/lib/permissions')>()
  const all = Object.values(mod.Permission) as string[]
  return {
    ...mod,
    Can: ({ children }: { children: ReactNode }) => (canMutate ? <>{children}</> : null),
    useHasPermission: () => true,
    useCanMutate: () => canMutate,
    usePermissions: () => ({
      permissions: canMutate ? all : [],
      isOwner: () => canMutate,
      can: () => canMutate,
      isLoading: false,
      tenantRole: canMutate ? 'owner' : 'viewer',
    }),
  }
})

const group = (over: Partial<Group>): Group => ({
  id: 'g',
  tenant_id: 't',
  slug: 'g',
  name: 'G',
  description: '',
  group_type: 'team',
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
  member_count: 0,
  asset_count: 0,
  ...over,
})
const APPSEC = group({
  id: 'appsec',
  name: 'AppSec',
  description: 'Owns code and web findings',
  group_type: 'security_team',
  member_count: 9,
  asset_count: 412,
})
const PENTEST = group({ id: 'pentest', name: 'Pentest (external)', group_type: 'external' })

let groupsState: { groups: Group[]; isError: boolean; error?: unknown }
vi.mock('@/features/access-control', async (orig) => ({
  ...(await orig<typeof import('@/features/access-control')>()),
  useGroups: () => ({ ...groupsState, isLoading: false, uniqueMemberCount: 0, mutate: vi.fn() }),
  useCreateGroup: () => ({ createGroup: vi.fn(), isCreating: false }),
  useDeleteGroup: () => ({ deleteGroup: vi.fn(), isDeleting: false }),
  useAssignmentRules: () => ({
    assignmentRules: [
      {
        id: 'r1',
        name: 'Code findings to AppSec',
        description: '',
        priority: 10,
        target_group_id: 'appsec',
        conditions: { finding_source: ['sast'] },
        options: {},
        is_active: true,
        created_by: 'u',
        created_at: '2026-10-01T00:00:00Z',
        updated_at: '2026-10-01T00:00:00Z',
      },
      {
        id: 'r2',
        name: 'Old DMZ hosts',
        description: '',
        priority: 90,
        target_group_id: 'appsec',
        conditions: { asset_type: ['host'] },
        options: {},
        is_active: false,
        created_by: 'u',
        created_at: '2026-10-01T00:00:00Z',
        updated_at: '2026-10-01T00:00:00Z',
      },
    ],
    isLoading: false,
    isError: false,
    mutate: vi.fn(),
  }),
  useCreateAssignmentRule: () => ({ createAssignmentRule: vi.fn(), isCreating: false }),
  useDeleteAssignmentRule: () => ({ deleteAssignmentRule: vi.fn(), isDeleting: false }),
}))
vi.mock('@/features/access-control/components/group-detail-sheet', () => ({
  GroupDetailSheet: () => null,
}))
vi.mock('@/features/access-control/components/assignment-rule-detail-sheet', () => ({
  AssignmentRuleDetailSheet: () => null,
}))
vi.mock('@/features/access-control/api/use-team-access', () => ({
  setTeamAccess: vi.fn(),
  useTeamPresetTemplates: () => ({ templates: [], isLoading: false }),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const show = (search = '') => {
  window.history.replaceState(null, '', `/settings/teams${search}`)
  return render(
    <I18nProvider locale="en">
      <TeamsPage />
    </I18nProvider>
  )
}

beforeEach(() => {
  canMutate = true
  groupsState = { groups: [APPSEC, PENTEST], isError: false }
})

describe('Teams page', () => {
  it('lists teams with kind and counts under one page frame with the tabs', () => {
    show()
    expect(screen.getByRole('heading', { level: 1, name: 'Teams' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Assignment rules' })).toBeInTheDocument()
    const table = screen.getByRole('table')
    expect(within(table).getByRole('link', { name: 'AppSec' })).toHaveAttribute(
      'href',
      '/settings/teams?team=appsec'
    )
    expect(within(table).getByText('Security team')).toBeInTheDocument()
    expect(within(table).getByText('412')).toBeInTheDocument()
    expect(screen.getByTestId('no-team-access-note')).toBeInTheDocument()
  })

  it('narrows by kind from the URL and shows it as a chip', () => {
    show('?kind=external')
    const table = screen.getByRole('table')
    expect(within(table).getByRole('link', { name: 'Pentest (external)' })).toBeInTheDocument()
    expect(within(table).queryByRole('link', { name: 'AppSec' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Remove filter Kind: External' })).toBeInTheDocument()
  })

  it('delete names the members and assets the team affects', async () => {
    const user = userEvent.setup()
    show()
    await user.click(screen.getAllByRole('button', { name: 'Actions for AppSec' })[0])
    await user.click(await screen.findByRole('menuitem', { name: /Delete team/ }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('9 members lose the access this team gives them')
    expect(dialog).toHaveTextContent('412 assets')
  })

  it('a reader without the create permission is told the page is view only', () => {
    canMutate = false
    show()
    expect(screen.getByText(/View only\. Only owners and administrators/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Create team/ })).toBeNull()
  })

  it('a failed read shows Retry, not an empty list', () => {
    groupsState = { groups: [], isError: true, error: new Error('boom') }
    show()
    expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument()
    expect(screen.queryByText('No teams yet')).toBeNull()
  })
})

describe('Assignment rules tab', () => {
  it('lists rules by priority with target team and status, and filters by status', () => {
    show('?tab=assignment-rules&status=inactive')
    const table = screen.getByRole('table')
    expect(within(table).getByRole('link', { name: 'Old DMZ hosts' })).toBeInTheDocument()
    expect(within(table).queryByRole('link', { name: 'Code findings to AppSec' })).toBeNull()
    expect(within(table).getByText('AppSec')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Remove filter Status: Inactive' })
    ).toBeInTheDocument()
  })

  it('the condition choices of a new rule are toggle buttons', async () => {
    const user = userEvent.setup()
    show('?tab=assignment-rules')
    await user.click(screen.getByRole('button', { name: /Create rule/ }))
    const dialog = await screen.findByRole('dialog')
    const critical = within(dialog).getByRole('button', { name: 'critical' })
    expect(critical).toHaveAttribute('aria-pressed', 'false')
    await user.click(critical)
    expect(critical).toHaveAttribute('aria-pressed', 'true')
  })
})
