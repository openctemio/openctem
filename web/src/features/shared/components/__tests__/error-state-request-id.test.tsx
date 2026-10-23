import { describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ErrorState } from '../error-state'

const copyToClipboard = vi.fn()
vi.mock('@/lib/clipboard', () => ({ copyToClipboard: (v: string) => copyToClipboard(v) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('ErrorState request id', () => {
  it('shows the request id and copies it', () => {
    const error = Object.assign(new Error('boom'), { statusCode: 500, requestId: 'req-42' })
    render(<ErrorState title="findings" error={error} onRetry={() => {}} />)
    expect(screen.getByText('req-42')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /copy request id/i }))
    expect(copyToClipboard).toHaveBeenCalledWith('req-42')
  })

  it('shows no copy button when the error has no request id', () => {
    render(<ErrorState title="findings" error={new Error('boom')} onRetry={() => {}} />)
    expect(screen.queryByRole('button', { name: /copy request id/i })).not.toBeInTheDocument()
  })

  it('keeps the request id out of the text on a phone (copy only)', () => {
    const error = Object.assign(new Error('boom'), { statusCode: 500, requestId: 'req-43' })
    render(<ErrorState title="findings" error={error} onRetry={() => {}} />)
    expect(screen.getByText('req-43')).toHaveClass('hidden', 'sm:inline')
  })
})

describe('ErrorState message', () => {
  it('explains a rate limit instead of echoing the server text', () => {
    const error = Object.assign(new Error('Rate limit exceeded'), { statusCode: 429 })
    render(<ErrorState title="tasks" error={error} onRetry={() => {}} />)
    expect(screen.queryByText('Rate limit exceeded')).not.toBeInTheDocument()
    expect(screen.getByText(/too many requests in a short time/i)).toBeInTheDocument()
  })

  it('explains a lost connection', () => {
    render(<ErrorState title="tasks" error={new TypeError('Failed to fetch')} onRetry={() => {}} />)
    expect(screen.getByText(/server could not be reached/i)).toBeInTheDocument()
  })

  it('keeps the server message for other errors', () => {
    const error = Object.assign(new Error('Campaign is archived'), { statusCode: 409 })
    render(<ErrorState title="campaign" error={error} onRetry={() => {}} />)
    expect(screen.getByText('Campaign is archived')).toBeInTheDocument()
  })
})
