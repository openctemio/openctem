import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { TeamAccessPanel } from '../team-access-panel'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

// The team's one Access tab: presets and scope, then the custom roles; the
// outside-member notice is said once.

const templates = vi.fn()
// Stable objects: the tab resets its form when the loaded access changes.
const teamAccess = {
  access: { presets: [], scope_mode: 'specific', other_roles: 1, privileged: false },
  error: undefined,
  isLoading: false,
  mutate: vi.fn(),
}
const groupRoles = { roles: [], error: undefined, isLoading: false, mutate: vi.fn() }
const roles = {
  roles: [{ id: 'r2', name: 'Full data access', is_system: false, has_full_data_access: true }],
}

vi.mock('../../../api/use-team-access', () => ({
  useTeamAccess: () => teamAccess,
  useTeamPresetTemplates: () => ({ templates: templates(), isLoading: false }),
  setTeamAccess: vi.fn(),
  upgradeTeamPreset: vi.fn(),
}))
vi.mock('../../../api/use-group-roles', () => ({
  useGroupRoles: () => groupRoles,
  bindGroupRole: vi.fn(),
  unbindGroupRole: vi.fn(),
}))
vi.mock('../../../api/use-roles', () => ({
  useRoles: () => roles,
  useRoleMembers: () => ({ members: [] }),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ isOwner: () => true, can: () => true, canAll: () => true }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const outsider = { user_id: 'u9', name: 'Pat Contractor' }
const fullDataPreset = {
  id: 't-full',
  name: 'Full data',
  has_full_data_access: true,
  privileged: true,
  description: '',
}

const withFullData = [fullDataPreset]
const none: never[] = []

function renderPanel() {
  return render(
    <TeamAccessPanel
      groupId="g1"
      canSetAccess
      canBind
      canUnbind
      outsideMembers={[outsider]}
      onShowOutside={vi.fn()}
    />
  )
}

describe('TeamAccessPanel', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows both sections, without pointing at a separate Roles tab', () => {
    templates.mockReturnValue(none)
    renderPanel()
    expect(screen.getByText('What members can do and see')).toBeInTheDocument()
    expect(screen.getByText('Custom roles')).toBeInTheDocument()
    expect(screen.queryByText(/Roles tab/)).not.toBeInTheDocument()
  })

  it('says the outside-member notice once when the presets show it', async () => {
    templates.mockReturnValue(withFullData)
    renderPanel()
    await waitFor(() => expect(screen.getAllByTestId('team-outside-notice')).toHaveLength(1))
    // The roles section keeps its direct-grant way forward.
    expect(screen.getByRole('button', { name: 'Give the role to a person' })).toBeInTheDocument()
  })

  it('lets the roles section say it when no preset offers full data', () => {
    templates.mockReturnValue(none)
    renderPanel()
    const notices = screen.getAllByTestId('team-outside-notice')
    expect(notices).toHaveLength(1)
    expect(notices[0]).toHaveTextContent('Pat Contractor')
  })
})
