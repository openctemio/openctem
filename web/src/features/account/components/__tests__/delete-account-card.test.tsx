import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { DeleteAccountCard } from '../delete-account-card'

const fetcherWithOptions = vi.fn()
let status: { scheduled: boolean; erase_after?: string } = { scheduled: false }
vi.mock('@/lib/api/client', () => ({
  fetcher: vi.fn(),
  fetcherWithOptions: (...a: unknown[]) => fetcherWithOptions(...a),
}))
vi.mock('swr', () => ({ default: () => ({ data: status }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('DeleteAccountCard', () => {
  const originalLocation = window.location
  const replace = vi.fn()
  beforeEach(() => {
    fetcherWithOptions.mockReset()
    replace.mockReset()
    status = { scheduled: false }
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...originalLocation, replace },
    })
  })
  afterEach(() => {
    Object.defineProperty(window, 'location', { configurable: true, value: originalLocation })
  })

  it('needs the email typed, then schedules the deletion and signs out', async () => {
    fetcherWithOptions.mockResolvedValue({ scheduled: true, erase_after: '2026-11-01T00:00:00Z' })
    const user = userEvent.setup()
    render(<DeleteAccountCard email="bob@acme.example" />)
    await user.click(screen.getByRole('button', { name: 'Delete my account' }))
    const buttons = screen.getAllByRole('button', { name: 'Delete my account' })
    const confirm = buttons[buttons.length - 1]
    expect(confirm).toBeDisabled()
    await user.type(screen.getByRole('textbox'), 'bob@acme.example')
    await user.click(confirm)
    await waitFor(() =>
      expect(fetcherWithOptions).toHaveBeenCalledWith('/api/v1/me/account', { method: 'DELETE' })
    )
    await waitFor(() => expect(replace).toHaveBeenCalledWith('/login'))
  })

  it('shows a pending deletion and that signing in cancels it', () => {
    status = { scheduled: true, erase_after: '2026-11-01T00:00:00Z' }
    render(<DeleteAccountCard email="bob@acme.example" />)
    expect(screen.getByText(/signing in cancels it/i)).toBeInTheDocument()
  })
})
