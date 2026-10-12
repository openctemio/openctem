/**
 * useMyGroups reads GET /api/v1/me/groups. It used to request
 * /api/v1/groups/me, which the API routes to /groups/{groupId} and answers
 * 400, so every list page with a saved-views menu sent a failing request and
 * "share with a group" never listed the user's groups.
 */
import { renderHook, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const fetcher = vi.fn()
vi.mock('@/lib/api/client', () => ({
  fetcher: (url: string) => fetcher(url),
  fetcherWithOptions: vi.fn(),
}))

import { MY_GROUPS_URL, useMyGroups } from '../use-groups'

function wrapper({ children }: { children: ReactNode }) {
  return (
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
  )
}

describe('useMyGroups', () => {
  beforeEach(() => fetcher.mockReset())

  it('requests the me/groups route, which the API serves', async () => {
    fetcher.mockResolvedValue([{ id: 'g1', name: 'SecOps' }])
    const { result } = renderHook(() => useMyGroups(), { wrapper })
    await waitFor(() => expect(result.current.groups).toHaveLength(1))
    expect(MY_GROUPS_URL).toBe('/api/v1/me/groups')
    expect(fetcher).toHaveBeenCalledWith('/api/v1/me/groups')
    expect(fetcher).not.toHaveBeenCalledWith('/api/v1/groups/me')
  })

  it('accepts the { groups } shape too', async () => {
    fetcher.mockResolvedValue({ groups: [{ id: 'g1' }, { id: 'g2' }] })
    const { result } = renderHook(() => useMyGroups(), { wrapper })
    await waitFor(() => expect(result.current.groups).toHaveLength(2))
  })
})
