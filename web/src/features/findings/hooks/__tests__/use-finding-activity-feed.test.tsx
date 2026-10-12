import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import type { ActivityCommentItem } from '@/features/activity/types'

const mockPost = vi.fn()
const mockPut = vi.fn()
const mockDel = vi.fn()
vi.mock('@/lib/api/client', () => ({
  get: vi.fn(async () => ({ data: [] })),
  post: (...a: unknown[]) => mockPost(...a),
  put: (...a: unknown[]) => mockPut(...a),
  del: (...a: unknown[]) => mockDel(...a),
}))

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))

vi.mock('../../api/use-finding-activities-api', () => ({
  useFindingActivitiesInfinite: () => ({
    activities: [],
    total: 0,
    isLoading: false,
    isLoadingMore: false,
    isReachingEnd: true,
    loadMore: vi.fn(),
    error: undefined,
    mutate: vi.fn(async () => undefined),
  }),
}))

vi.mock('../use-activity-stream', () => ({
  useActivityStream: () => ({ realtimeActivities: [], status: 'idle', clearActivities: vi.fn() }),
}))

import { useFindingActivityFeed } from '../use-finding-activity-feed'

function wrapper({ children }: { children: ReactNode }) {
  return (
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
  )
}

const item = { commentId: 'c1' } as ActivityCommentItem

describe('useFindingActivityFeed comment routes', () => {
  beforeEach(() => {
    mockPost.mockReset().mockResolvedValue({ data: [] })
    mockPut.mockReset().mockResolvedValue({})
    mockDel.mockReset().mockResolvedValue({ data: [] })
  })

  // A pentest finding's comments are edited, deleted and reacted to through
  // the pentest routes, open to every campaign member (clients included).
  it('uses the pentest routes on a pentest finding', async () => {
    const { result } = renderHook(
      () => useFindingActivityFeed('f1', { pentest: true, live: false }),
      { wrapper }
    )
    await act(async () => {
      await result.current.editComment(item, 'new text')
      await result.current.deleteComment(item)
      await result.current.toggleReaction(item, '👍', true)
      await result.current.toggleReaction(item, '👍', false)
    })
    expect(mockPut).toHaveBeenCalledWith('/api/v1/pentest/findings/f1/comments/c1', {
      content: 'new text',
    })
    expect(mockDel).toHaveBeenCalledWith('/api/v1/pentest/findings/f1/comments/c1')
    expect(mockPost).toHaveBeenCalledWith('/api/v1/pentest/findings/f1/comments/c1/reactions', {
      emoji: '👍',
    })
    expect(mockDel).toHaveBeenCalledWith(
      `/api/v1/pentest/findings/f1/comments/c1/reactions?emoji=${encodeURIComponent('👍')}`
    )
  })

  it('keeps the finding routes elsewhere', async () => {
    const { result } = renderHook(() => useFindingActivityFeed('f1', { live: false }), {
      wrapper,
    })
    await act(async () => {
      await result.current.editComment(item, 'new text')
      await result.current.deleteComment(item)
      await result.current.toggleReaction(item, '👍', true)
      await result.current.toggleReaction(item, '👍', false)
    })
    expect(mockPut).toHaveBeenCalledWith('/api/v1/findings/f1/comments/c1', { content: 'new text' })
    expect(mockDel).toHaveBeenCalledWith('/api/v1/findings/f1/comments/c1')
    expect(mockPost).toHaveBeenCalledWith('/api/v1/comments/c1/reactions', { emoji: '👍' })
    expect(mockDel).toHaveBeenCalledWith(
      `/api/v1/comments/c1/reactions/${encodeURIComponent('👍')}`
    )
  })
})
