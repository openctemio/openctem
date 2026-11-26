import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'

import { registerStepUpHandler } from '@/lib/api/step-up'
import {
  applyRoleTemplateUpdate,
  useAssignRole,
  useBulkAssignRoleMembers,
  useCreateRole,
  useDeleteRole,
  useSetUserRoles,
  useUpdateRole,
} from '../use-roles'

// Role writes need a recent sign-in on the server (403 STEP_UP_REQUIRED).
// The role hooks go through the shared client, so the re-authentication
// dialog opens and the same request is retried once; cancelling keeps the
// refusal.

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}
const stepUp = () => json(403, { code: 'STEP_UP_REQUIRED', message: 'Confirm your identity' })

describe('role writes and step-up', () => {
  const fetchMock = vi.fn()
  let unregister: (() => void) | null = null
  const handler = vi.fn(async () => true)

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    unregister = registerStepUpHandler(handler)
  })
  afterEach(() => {
    unregister?.()
    vi.unstubAllGlobals()
    fetchMock.mockReset()
    handler.mockReset()
    handler.mockImplementation(async () => true)
  })

  // Each case renders its hook first and returns the call that sends.
  const cases: [string, () => () => Promise<unknown>][] = [
    [
      'create a role',
      () => {
        const { result } = renderHook(() => useCreateRole())
        return () =>
          result.current.createRole({ slug: 'auditors', name: 'Auditors', permissions: [] })
      },
    ],
    [
      'update a role',
      () => {
        const { result } = renderHook(() => useUpdateRole('r1'))
        return () => result.current.updateRole({ name: 'Auditors 2' })
      },
    ],
    [
      'delete a role',
      () => {
        const { result } = renderHook(() => useDeleteRole('r1'))
        return () => result.current.deleteRole()
      },
    ],
    [
      'assign a role',
      () => {
        const { result } = renderHook(() => useAssignRole('u1'))
        return () => result.current.assignRole({ role_id: 'r1' })
      },
    ],
    [
      'set user roles',
      () => {
        const { result } = renderHook(() => useSetUserRoles('u1'))
        return () => result.current.setUserRoles({ role_ids: ['r1'] })
      },
    ],
    [
      'bulk assign a role',
      () => {
        const { result } = renderHook(() => useBulkAssignRoleMembers('r1'))
        return () => result.current.bulkAssignMembers({ user_ids: ['u1', 'u2'] })
      },
    ],
    ['apply a template update', () => () => applyRoleTemplateUpdate('r1', 2)],
  ]

  it.each(cases)('%s re-authenticates and retries once', async (_name, setup) => {
    const send = setup()
    fetchMock.mockResolvedValueOnce(stepUp()).mockResolvedValueOnce(json(200, {}))
    await act(async () => {
      await send()
    })
    expect(handler).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    const [first, second] = fetchMock.mock.calls
    expect(second[0]).toBe(first[0])
    expect((second[1] as RequestInit).method).toBe((first[1] as RequestInit).method)
  })

  it('cancelling the prompt keeps the refusal and sends nothing more', async () => {
    handler.mockImplementation(async () => false)
    fetchMock.mockResolvedValueOnce(stepUp())
    const { result } = renderHook(() => useCreateRole())
    let error: { code?: string } | undefined
    await act(async () => {
      try {
        await result.current.createRole({ slug: 'auditors', name: 'Auditors', permissions: [] })
      } catch (e) {
        error = e as { code?: string }
      }
    })
    expect(error?.code).toBe('STEP_UP_REQUIRED')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
