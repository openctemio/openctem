/**
 * No raw user id or system string reaches the screen (research/53 §4.6).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const perms = vi.hoisted(() => ({ members: true }))
const members = vi.hoisted(() => ({
  list: [{ user_id: 'u-1', name: 'Nguyen Manh', email: 'secret@acme.io' }],
}))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    usePermissions: () => ({
      can: (p: string) => p !== actual.Permission.MembersRead || perms.members,
    }),
  }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
vi.mock('@/features/organization/api/use-members', () => ({
  useMembers: (tenant: string | undefined) => ({
    members: tenant ? members.list : [],
    isLoading: false,
  }),
}))

const { ActorChip, toActorRef } = await import('../actor-chip')

beforeEach(() => {
  perms.members = true
})

describe('ActorChip', () => {
  it('shows a member by name, never the id or e-mail', () => {
    render(<ActorChip actor="u-1" />)
    expect(screen.getByText('Nguyen Manh')).toBeInTheDocument()
    expect(screen.queryByText('u-1')).not.toBeInTheDocument()
    expect(screen.queryByText(/secret@acme.io/)).not.toBeInTheDocument()
  })

  it('an id this organization does not hold reads "Former member"', () => {
    render(<ActorChip actor="0190a1b2-0000-7000-8000-000000000000" />)
    expect(screen.getByText('Former member')).toBeInTheDocument()
  })

  it('without member access it reads "A team member", not the id', () => {
    perms.members = false
    render(<ActorChip actor="u-1" />)
    expect(screen.getByText('A team member')).toBeInTheDocument()
  })

  it('turns system strings into words', () => {
    render(<ActorChip actor="system:migration-000292" />)
    expect(screen.getByText('OpenCTEM upgrade (wildcard rule change)')).toBeInTheDocument()
    expect(screen.queryByText(/000292/)).not.toBeInTheDocument()
  })

  it('takes the API actor object as is', () => {
    render(<ActorChip actor={{ kind: 'user', id: 'x', name: 'Lan' }} />)
    expect(screen.getByText('Lan')).toBeInTheDocument()
    expect(toActorRef({ kind: 'system', code: 'review_rule' })).toEqual({
      kind: 'system',
      code: 'review_rule',
    })
  })
})
