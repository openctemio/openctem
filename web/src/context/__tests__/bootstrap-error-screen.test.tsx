/**
 * The bootstrap failure screen: a refused (429) bootstrap reads as a busy
 * server and retries on its own; any other failure reads as unreachable.
 * Both speak the app's language.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen } from '@testing-library/react'

vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (key: string, fallback?: string) =>
      key === 'common.bootstrap.busyTitle' ? 'Máy chủ đang bận' : (fallback ?? key),
    locale: 'vi',
  }),
}))

import { ConnectionErrorScreen, RATE_LIMIT_RETRY_MS } from '../bootstrap-provider'

afterEach(() => vi.useRealTimers())

describe('ConnectionErrorScreen', () => {
  it('says the server is unreachable and never retries by itself', () => {
    vi.useFakeTimers()
    const onRetry = vi.fn()
    render(<ConnectionErrorScreen retrying={false} onRetry={onRetry} />)
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Can’t reach the server')
    expect(screen.getByRole('main')).toBeInTheDocument()
    act(() => vi.advanceTimersByTime(RATE_LIMIT_RETRY_MS * 2))
    expect(onRetry).not.toHaveBeenCalled()
  })

  it('reads a rate limit as a busy server, in the app language, and retries once after a pause', () => {
    vi.useFakeTimers()
    const onRetry = vi.fn()
    render(<ConnectionErrorScreen retrying={false} onRetry={onRetry} rateLimited />)
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Máy chủ đang bận')
    act(() => vi.advanceTimersByTime(RATE_LIMIT_RETRY_MS - 1))
    expect(onRetry).not.toHaveBeenCalled()
    act(() => vi.advanceTimersByTime(1))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('does not stack a timer while a retry is running', () => {
    vi.useFakeTimers()
    const onRetry = vi.fn()
    render(<ConnectionErrorScreen retrying onRetry={onRetry} rateLimited />)
    act(() => vi.advanceTimersByTime(RATE_LIMIT_RETRY_MS * 2))
    expect(onRetry).not.toHaveBeenCalled()
  })
})
