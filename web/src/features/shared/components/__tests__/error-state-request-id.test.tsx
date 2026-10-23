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
})
