import { act, renderHook } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { toast } from 'sonner'
import { useMarkNotifications } from '../use-mark-notifications'
import * as api from '../use-notification-api'

vi.mock('sonner', () => ({ toast: { error: vi.fn() } }))
vi.mock('../use-notification-api', () => ({
  markNotificationAsRead: vi.fn(),
  markAllNotificationsAsRead: vi.fn(),
  invalidateNotificationsCache: vi.fn(),
}))

beforeEach(() => vi.clearAllMocks())

describe('useMarkNotifications', () => {
  it('tells the user when marking one notification read fails', async () => {
    vi.mocked(api.markNotificationAsRead).mockRejectedValue(new Error('500'))
    const { result } = renderHook(() => useMarkNotifications())
    await act(async () => {
      result.current.markRead('n1')
    })
    expect(toast.error).toHaveBeenCalledTimes(1)
  })

  it('tells the user when mark all fails, and refreshes on success', async () => {
    vi.mocked(api.markAllNotificationsAsRead).mockRejectedValueOnce(new Error('500'))
    const { result } = renderHook(() => useMarkNotifications())
    await act(async () => {
      await result.current.markAllRead()
    })
    expect(toast.error).toHaveBeenCalledTimes(1)
    vi.mocked(api.markAllNotificationsAsRead).mockResolvedValueOnce(undefined)
    await act(async () => {
      await result.current.markAllRead()
    })
    expect(api.invalidateNotificationsCache).toHaveBeenCalledTimes(1)
    expect(toast.error).toHaveBeenCalledTimes(1)
  })
})
