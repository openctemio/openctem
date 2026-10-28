import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AIAnalystsSection } from '../ai-analysts-section'
import type { AIAnalyst } from '../../api/use-ai-analysts'

let canManage = true
let analysts: AIAnalyst[] = []
const mutate = vi.fn()
const create = vi.fn()
const action = vi.fn()

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => canManage }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', slug: 'acme', role: 'owner' } }),
}))
vi.mock('@/stores/auth-store', () => ({
  useAuthStore: (sel: (s: { user: { id: string } }) => unknown) => sel({ user: { id: 'u-me' } }),
}))
vi.mock('@/features/organization/api/use-members', () => ({
  useMembers: () => ({
    members: [
      { user_id: 'u1', name: 'Jamie', email: 'j@x.test' },
      { user_id: 'u2', name: 'Sam', email: 's@x.test' },
    ],
    isLoading: false,
  }),
}))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useGroups: () => ({
    groups: [{ id: 'g1', name: 'AppSec', group_type: 'security_team', is_active: true }],
    isLoading: false,
  }),
}))
vi.mock('../../api/use-ai-analysts', async (orig) => ({
  ...(await orig<typeof import('../../api/use-ai-analysts')>()),
  useAIAnalysts: () => ({ data: analysts, isLoading: false, mutate }),
  createAIAnalyst: (...a: unknown[]) => create(...a),
  runAIAnalystAction: (...a: unknown[]) => action(...a),
}))

const bot: AIAnalyst = {
  id: 'an1',
  name: 'Triage bot',
  preset: 'triage',
  status: 'paused',
  pause_reason: 'attestation_expired',
  attest_due_at: '2026-11-01T00:00:00Z',
  owners: [
    { kind: 'user', id: 'u1', name: 'Jamie' },
    { kind: 'team', id: 'g1', name: 'AppSec' },
  ],
  created_at: '2026-10-01T00:00:00Z',
}

describe('AI analysts section', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    canManage = true
    analysts = [bot]
  })

  it('lists analysts with preset, status and reason, and accountable owners', () => {
    render(<AIAnalystsSection />)
    const row = screen.getByTestId('ai-analyst-row')
    expect(row).toHaveTextContent('Triage bot')
    expect(row).toHaveTextContent('Triage')
    expect(row).toHaveTextContent('Paused')
    expect(row).toHaveTextContent('Attestation overdue')
    expect(row).toHaveTextContent('Jamie, AppSec')
  })

  it('shows an empty state when there are none', () => {
    analysts = []
    render(<AIAnalystsSection />)
    expect(screen.getByText('No AI analysts yet')).toBeInTheDocument()
  })

  it('creates an analyst with the chosen owners', async () => {
    create.mockResolvedValue({ ...bot, id: 'new' })
    const user = userEvent.setup()
    render(<AIAnalystsSection />)
    await user.click(screen.getByRole('button', { name: 'New AI analyst' }))
    const create_ = screen.getByRole('button', { name: 'Create' })
    expect(create_).toBeDisabled()
    await user.type(screen.getByLabelText('Name'), 'Night shift')
    await user.type(screen.getByLabelText('Description (optional)'), 'Reads new findings')
    await user.click(screen.getByLabelText('Jamie'))
    await user.click(screen.getByLabelText('AppSec'))
    await user.click(create_)
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith({
        name: 'Night shift',
        description: 'Reads new findings',
        preset: 'suggest',
        owners: [
          { kind: 'user', id: 'u1' },
          { kind: 'team', id: 'g1' },
        ],
      })
    )
    expect(mutate).toHaveBeenCalled()
  })

  it('resumes after a confirmation', async () => {
    action.mockResolvedValue(bot)
    const user = userEvent.setup()
    render(<AIAnalystsSection />)
    await user.click(screen.getByRole('button', { name: 'Actions for Triage bot' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Resume' }))
    await user.click(await screen.findByRole('button', { name: 'Resume' }))
    await waitFor(() => expect(action).toHaveBeenCalledWith('an1', 'resume'))
  })

  it('hides the manage actions without service_accounts:manage', async () => {
    canManage = false
    const user = userEvent.setup()
    render(<AIAnalystsSection />)
    expect(screen.queryByRole('button', { name: 'New AI analyst' })).toBeNull()
    // The viewer is not an accountable owner: no row action at all.
    expect(screen.queryByRole('button', { name: 'Actions for Triage bot' })).toBeNull()
    expect(user).toBeDefined()
  })

  it('lets an accountable owner attest without the manage permission', async () => {
    canManage = false
    analysts = [{ ...bot, status: 'active', owners: [{ kind: 'user', id: 'u-me', name: 'Me' }] }]
    const user = userEvent.setup()
    render(<AIAnalystsSection />)
    await user.click(screen.getByRole('button', { name: 'Actions for Triage bot' }))
    expect(await screen.findByRole('menuitem', { name: 'Attest' })).toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: 'Delete' })).toBeNull()
    expect(screen.queryByRole('menuitem', { name: 'Change owners' })).toBeNull()
  })
})
