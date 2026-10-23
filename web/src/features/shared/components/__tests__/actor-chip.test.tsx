/**
 * No raw user id or system string reaches the screen (research/53 §4.6).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'

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
// The chip asks the members list for exactly the ids it shows (user_ids).
const fetcherMock = vi.hoisted(() => vi.fn())
vi.mock('@/lib/api/client', () => ({ fetcher: fetcherMock }))

const { ActorChip, toActorRef } = await import('../actor-chip')

const renderChip = (ui: React.ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map() }}>{ui}</SWRConfig>)

beforeEach(() => {
  perms.members = true
  fetcherMock.mockReset()
  fetcherMock.mockImplementation(async (url: string) => {
    const ids = (new URL(url, 'http://x').searchParams.get('user_ids') ?? '').split(',')
    return { data: members.list.filter((m) => ids.includes(m.user_id)) }
  })
})

describe('ActorChip', () => {
  it('shows a member by name, never the id or e-mail', async () => {
    renderChip(<ActorChip actor="u-1" />)
    expect(await screen.findByText('Nguyen Manh')).toBeInTheDocument()
    expect(screen.queryByText('u-1')).not.toBeInTheDocument()
    expect(screen.queryByText(/secret@acme.io/)).not.toBeInTheDocument()
  })

  it('an id this organization does not hold reads "Former member"', async () => {
    renderChip(<ActorChip actor="0190a1b2-0000-7000-8000-000000000000" />)
    expect(await screen.findByText('Former member')).toBeInTheDocument()
  })

  it('resolves members past the first 100 by id, in one batched request', async () => {
    members.list = [
      { user_id: 'u-150', name: 'Late Joiner', email: 'a@acme.io' },
      { user_id: 'u-151', name: 'Another One', email: 'b@acme.io' },
    ]
    renderChip(
      <>
        <ActorChip actor="u-150" />
        <ActorChip actor="u-151" />
        <ActorChip actor="u-150" />
      </>
    )
    await waitFor(() => expect(screen.getAllByText('Late Joiner')).toHaveLength(2))
    expect(screen.getByText('Another One')).toBeInTheDocument()
    expect(fetcherMock).toHaveBeenCalledTimes(1)
    expect(decodeURIComponent(String(fetcherMock.mock.calls[0][0]))).toContain(
      'user_ids=u-150,u-151'
    )
    members.list = [{ user_id: 'u-1', name: 'Nguyen Manh', email: 'secret@acme.io' }]
  })

  it('does not claim "Former member" when the lookup fails', async () => {
    fetcherMock.mockRejectedValue(new Error('boom'))
    renderChip(<ActorChip actor="u-1" />)
    await waitFor(() => expect(fetcherMock).toHaveBeenCalled())
    expect(screen.queryByText('Former member')).not.toBeInTheDocument()
    expect(screen.getByText('A team member')).toBeInTheDocument()
  })

  it('without member access it reads "A team member", not the id', () => {
    perms.members = false
    renderChip(<ActorChip actor="u-1" />)
    expect(screen.getByText('A team member')).toBeInTheDocument()
    expect(fetcherMock).not.toHaveBeenCalled()
  })

  it('turns system strings into words', () => {
    renderChip(<ActorChip actor="system:migration-000292" />)
    expect(screen.getByText('OpenCTEM upgrade (wildcard rule change)')).toBeInTheDocument()
    expect(screen.queryByText(/000292/)).not.toBeInTheDocument()
  })

  it('takes the API actor object as is', () => {
    renderChip(<ActorChip actor={{ kind: 'user', id: 'x', name: 'Lan' }} />)
    expect(screen.getByText('Lan')).toBeInTheDocument()
    expect(toActorRef({ kind: 'system', code: 'review_rule' })).toEqual({
      kind: 'system',
      code: 'review_rule',
    })
  })
})
