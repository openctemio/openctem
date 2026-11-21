import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useOwnerLabels } from '../api/use-owner-names'

const useMembers = vi.fn()
const useGroups = vi.fn()
vi.mock('@/features/organization/api/use-members', () => ({
  useMembers: (...a: unknown[]) => useMembers(...a),
}))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useGroups: (...a: unknown[]) => useGroups(...a),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't-1' } }),
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}))

beforeEach(() => {
  useMembers.mockReset().mockReturnValue({ members: [] })
  useGroups.mockReset().mockReturnValue({ groups: [] })
})

describe('useOwnerLabels', () => {
  it('reads nothing when there is no id to name', () => {
    renderHook(() => useOwnerLabels([undefined], [undefined]))
    expect(useMembers).toHaveBeenCalledWith(undefined, expect.anything())
    expect(useGroups).toHaveBeenCalledWith(undefined, false)
  })

  it('asks for the given people by id (sorted, once each), never the whole list', () => {
    useMembers.mockReturnValue({ members: [{ user_id: 'u-2', name: 'Sam', email: 's@x' }] })
    const { result } = renderHook(() => useOwnerLabels(['u-2', 'u-1', 'u-2'], []))
    expect(useMembers).toHaveBeenCalledWith('t-1', { userIds: ['u-1', 'u-2'], limit: 2 })
    expect(result.current.user('u-2')).toBe('Sam')
    expect(result.current.user('u-1')).toBeUndefined()
  })

  it('reads the teams only when a team id is given', () => {
    renderHook(() => useOwnerLabels([], ['g-1']))
    expect(useGroups).toHaveBeenCalledWith(undefined, true)
  })
})
