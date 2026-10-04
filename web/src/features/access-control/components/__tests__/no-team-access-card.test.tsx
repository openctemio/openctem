import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { NoTeamAccessCard } from '../no-team-access-card'

const mockUpdate = vi.fn()
const mockMutate = vi.fn()
let mockPolicy: 'everything' | 'nothing' | undefined = 'everything'
let mockIsAdmin = true
let mockIsOwner = true
let mockImpact:
  | {
      members_without_group_see: 'everything' | 'nothing'
      total_count: number
      members: { user_id: string; name: string; email: string; role: string }[]
    }
  | undefined

vi.mock('@/features/organization/api/use-data-scope-policy', () => ({
  useDataScopePolicy: () => ({
    policy: mockPolicy,
    isLoading: false,
    isError: false,
    mutate: mockMutate,
  }),
  useUpdateDataScopePolicy: () => ({ updatePolicy: mockUpdate, isUpdating: false }),
  useDataScopeImpact: () => ({
    impact: mockImpact,
    isLoading: false,
    isError: false,
    mutate: vi.fn(),
  }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ isAdmin: () => mockIsAdmin, isOwner: () => mockIsOwner }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const member = (n: number) => ({
  user_id: `u${n}`,
  name: `Member ${n}`,
  email: `m${n}@example.com`,
  role: 'member',
})

describe('NoTeamAccessCard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPolicy = 'everything'
    mockIsAdmin = true
    mockIsOwner = true
    mockImpact = { members_without_group_see: 'everything', total_count: 0, members: [] }
  })

  it('is hidden from members who are not owner or admin', () => {
    mockIsAdmin = false
    const { container } = render(<NoTeamAccessCard />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the current policy', () => {
    render(<NoTeamAccessCard />)
    expect(screen.getByText('Members without a team')).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: 'Everything (being retired)' })).toBeChecked()
    expect(screen.getByRole('radio', { name: 'Nothing' })).not.toBeChecked()
  })

  it('names the members who would see nothing after the switch', () => {
    mockImpact = {
      members_without_group_see: 'everything',
      total_count: 12,
      members: Array.from({ length: 12 }, (_, i) => member(i + 1)),
    }
    render(<NoTeamAccessCard />)
    expect(screen.getByText(/12 members are in no team and would see nothing/)).toBeInTheDocument()
    expect(screen.getByText(/Member 1, Member 2/)).toBeInTheDocument()
    expect(screen.getByText(/and 2 more/)).toBeInTheDocument()
  })

  it('asks before hiding data, and saves only on confirm', async () => {
    mockUpdate.mockResolvedValueOnce({ members_without_group_see: 'nothing' })
    render(<NoTeamAccessCard />)

    await userEvent.click(screen.getByRole('radio', { name: 'Nothing' }))
    expect(mockUpdate).not.toHaveBeenCalled()
    expect(screen.getByText('Hide data from members without a team?')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Hide data' }))
    expect(mockUpdate).toHaveBeenCalledWith('nothing')
  })

  it('cancelling the confirmation changes nothing', async () => {
    render(<NoTeamAccessCard />)
    await userEvent.click(screen.getByRole('radio', { name: 'Nothing' }))
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  it('cannot switch back to everything', async () => {
    mockPolicy = 'nothing'
    render(<NoTeamAccessCard />)
    const everything = screen.getByRole('radio', { name: 'Everything (being retired)' })
    expect(everything).toBeDisabled()
    await userEvent.click(everything)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  it('only the owner can switch', () => {
    mockIsOwner = false
    render(<NoTeamAccessCard />)
    expect(screen.getByRole('radio', { name: 'Nothing' })).toBeDisabled()
    expect(screen.getByText(/Only the owner can switch/)).toBeInTheDocument()
  })
})
