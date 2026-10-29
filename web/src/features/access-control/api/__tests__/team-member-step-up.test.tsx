import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'

import { getErrorMessage } from '@/lib/api/error-handler'
import { getDictionary, translate } from '@/lib/i18n'
import { registerStepUpHandler } from '@/lib/api/step-up'
import { useAddGroupMember, useRemoveGroupMember } from '../use-groups'
import { setGroupMemberExpiry } from '../use-group-roles'

// Changing the members of a team that carries a privileged role asks the
// owner for a recent sign-in (403 STEP_UP_REQUIRED). The member hooks go
// through the shared client, so the re-authentication dialog opens and the
// request is retried once. A refusal for any other reason keeps its own code.

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}
const stepUp = () => json(403, { code: 'STEP_UP_REQUIRED', message: 'Confirm your identity' })

describe('team member changes and step-up', () => {
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
    handler.mockClear()
  })

  it('add member re-authenticates and retries once', async () => {
    fetchMock.mockResolvedValueOnce(stepUp()).mockResolvedValueOnce(json(201, {}))
    const { result } = renderHook(() => useAddGroupMember('g1'))
    await act(async () => {
      await result.current.addMember({ user_id: 'u1', role: 'member' })
    })
    expect(handler).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock.mock.calls[1][0]).toBe(fetchMock.mock.calls[0][0])
  })

  it('remove member re-authenticates and retries once', async () => {
    fetchMock
      .mockResolvedValueOnce(stepUp())
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const { result } = renderHook(() => useRemoveGroupMember('g1', 'u1'))
    await act(async () => {
      await result.current.removeMember()
    })
    expect(handler).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('extend member re-authenticates and retries once', async () => {
    fetchMock.mockResolvedValueOnce(stepUp()).mockResolvedValueOnce(json(200, {}))
    await setGroupMemberExpiry('g1', 'u1', { expires_at: null })
    expect(handler).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('shows the owner-only sentence, not the generic permission text', async () => {
    fetchMock.mockResolvedValueOnce(
      json(403, { code: 'TEAM_PRIVILEGED_OWNER_ONLY', message: 'Only the organization owner' })
    )
    const { result } = renderHook(() => useAddGroupMember('g1'))
    let error: unknown
    await act(async () => {
      try {
        await result.current.addMember({ user_id: 'u1', role: 'member' })
      } catch (e) {
        error = e
      }
    })
    expect(handler).not.toHaveBeenCalled()
    const text = getErrorMessage(error, 'Failed to add member')
    expect(text).toBe(translate(getDictionary('en'), 'errors.TEAM_PRIVILEGED_OWNER_ONLY', ''))
    expect(text).toContain('Only the organization owner')
    expect(text).not.toContain('do not have permission')
  })
})
