import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import { ActorChip } from './actor-chip'

const fetcherMock = vi.fn()
vi.mock('@/lib/api/client', () => ({ fetcher: (...a: unknown[]) => fetcherMock(...a) }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 'tenant-1' } }) }))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({ t: (_k: string, fb: string) => fb }),
}))
const perms = { allowed: true }
vi.mock('@/lib/permissions', () => ({
  Permission: { MembersRead: 'members:read' },
  usePermissions: () => ({ can: () => perms.allowed }),
}))

const wrap = (ui: React.ReactNode) => (
  <SWRConfig value={{ provider: () => new Map() }}>{ui}</SWRConfig>
)

describe('ActorChip member lookup', () => {
  beforeEach(() => {
    fetcherMock.mockReset()
    perms.allowed = true
  })

  it('resolves a member beyond the first 100 by id, in one batched request', async () => {
    fetcherMock.mockResolvedValue({
      data: [
        { user_id: 'user-150', name: 'Late Joiner' },
        { user_id: 'user-151', name: 'Another One' },
      ],
    })
    render(
      wrap(
        <>
          <ActorChip actor="user-150" />
          <ActorChip actor="user-151" />
          <ActorChip actor="user-150" />
        </>
      )
    )
    await waitFor(() => expect(screen.getAllByText('Late Joiner').length).toBe(2))
    expect(screen.getByText('Another One')).toBeTruthy()
    expect(fetcherMock).toHaveBeenCalledTimes(1)
    const url = String(fetcherMock.mock.calls[0][0])
    expect(url).toContain('/members?')
    expect(decodeURIComponent(url)).toContain('user_ids=user-150,user-151')
  })

  it('says Former member only when the id is not a member', async () => {
    fetcherMock.mockResolvedValue({ data: [] })
    render(wrap(<ActorChip actor="gone-user" />))
    await waitFor(() => expect(screen.getByText('Former member')).toBeTruthy())
  })

  it('does not claim Former member when the lookup fails or is not allowed', async () => {
    fetcherMock.mockRejectedValue(new Error('boom'))
    render(wrap(<ActorChip actor="user-1" />))
    await waitFor(() => expect(fetcherMock).toHaveBeenCalled())
    expect(screen.queryByText('Former member')).toBeNull()
    expect(screen.getByText('A team member')).toBeTruthy()
  })

  it('makes no request without members:read', () => {
    perms.allowed = false
    render(wrap(<ActorChip actor="user-1" />))
    expect(fetcherMock).not.toHaveBeenCalled()
    expect(screen.getByText('A team member')).toBeTruthy()
  })
})
