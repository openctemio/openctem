/**
 * Retest check hooks (research/221)
 * - GET reads the finding's check from the finding-scoped route
 * - validate posts the body and saves nothing
 * - save PUTs the body, then refreshes the check and the retest list
 * - remove DELETEs and refreshes; approve POSTs to /approve
 * - no request without a current organization
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { SWRConfig } from 'swr'
import {
  retestCheckEndpoint,
  shortDigest,
  useApproveRetestCheck,
  useFindingRetestCheck,
  useRemoveRetestCheck,
  useSaveRetestCheck,
  useValidateRetestCheck,
  type RetestCheckPutBody,
} from '../use-finding-retest-check'

const mockGet = vi.fn()
const mockPost = vi.fn()
const mockPut = vi.fn()
const mockDel = vi.fn()
vi.mock('@/lib/api/client', () => ({
  get: (...a: unknown[]) => mockGet(...a),
  post: (...a: unknown[]) => mockPost(...a),
  put: (...a: unknown[]) => mockPut(...a),
  del: (...a: unknown[]) => mockDel(...a),
}))

let mockTenant: { id: string } | null = { id: 't-1' }
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: mockTenant }),
}))

function wrapper({ children }: { children: ReactNode }) {
  return (
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
  )
}

const body: RetestCheckPutBody = {
  kind: 'http_assertion',
  assertion: {
    method: 'GET',
    path: '/search?q=x',
    matchers: [{ type: 'word', part: 'body', words: ['<script>x</script>'] }],
  },
}

describe('use-finding-retest-check', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockTenant = { id: 't-1' }
    mockGet.mockResolvedValue({ check: null })
  })

  it('shortens a digest to 12 hex characters', () => {
    expect(shortDigest('sha256:abcdef1234567890abcdef')).toBe('sha256:abcdef123456')
    expect(shortDigest('')).toBe('')
    expect(shortDigest(undefined)).toBe('')
  })

  it('reads the check from the finding route', async () => {
    const { result } = renderHook(() => useFindingRetestCheck('f-1'), { wrapper })
    await waitFor(() => expect(result.current.data).toEqual({ check: null }))
    expect(mockGet).toHaveBeenCalledWith('/api/v1/findings/f-1/retest-check')
  })

  it('makes no request without a current organization', () => {
    mockTenant = null
    renderHook(() => useFindingRetestCheck('f-1'), { wrapper })
    expect(mockGet).not.toHaveBeenCalled()
  })

  it('validates without saving', async () => {
    mockPost.mockResolvedValue({ valid: true, errors: [], tier: 'T0' })
    const { result } = renderHook(() => useValidateRetestCheck('f-1'), { wrapper })
    await act(async () => {
      await result.current.trigger(body)
    })
    expect(mockPost).toHaveBeenCalledWith('/api/v1/findings/f-1/retest-check/validate', body)
    expect(mockPut).not.toHaveBeenCalled()
  })

  it('saves with PUT and refreshes the check and the retest list', async () => {
    mockPut.mockResolvedValue({ id: 'c-1' })
    const { result } = renderHook(
      () => ({ check: useFindingRetestCheck('f-1'), save: useSaveRetestCheck('f-1') }),
      { wrapper }
    )
    await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(1))
    await act(async () => {
      await result.current.save.trigger(body)
    })
    expect(mockPut).toHaveBeenCalledWith(retestCheckEndpoint('f-1'), body)
    // The mounted check query was revalidated after the save.
    await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2))
  })

  it('removes with DELETE and approves with POST /approve', async () => {
    mockDel.mockResolvedValue(undefined)
    mockPost.mockResolvedValue({ id: 'c-1' })
    const { result } = renderHook(
      () => ({ remove: useRemoveRetestCheck('f-1'), approve: useApproveRetestCheck('f-1') }),
      { wrapper }
    )
    await act(async () => {
      await result.current.remove.trigger()
    })
    expect(mockDel).toHaveBeenCalledWith('/api/v1/findings/f-1/retest-check')
    await act(async () => {
      await result.current.approve.trigger()
    })
    expect(mockPost).toHaveBeenCalledWith('/api/v1/findings/f-1/retest-check/approve', {})
  })

  it('encodes the finding id into the route', () => {
    expect(retestCheckEndpoint('a/b')).toBe('/api/v1/findings/a%2Fb/retest-check')
  })
})
