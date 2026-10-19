import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiClientError } from '@/lib/api/error-handler'

const get = vi.fn()
const post = vi.fn()
const toastError = vi.fn()
const state = { canRebuild: true }

vi.mock('@/lib/api/client', () => ({
  get: (...a: unknown[]) => get(...a),
  post: (...a: unknown[]) => post(...a),
}))
vi.mock('@/lib/permissions', () => ({ useCanMutate: () => state.canRebuild }))
vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: (...a: unknown[]) => toastError(...a) },
}))

import { DashboardDataCard, type DashboardDataStatus } from '../dashboard-data-card'

const built: DashboardDataStatus = {
  rebuilt_at: '2026-10-18T02:00:00Z',
  reconciled_at: '2026-10-18T02:00:00Z',
  last_drift: 0,
  rebuild_requested_at: null,
  pending: false,
  queue_depth: 3,
  next_rebuild_at: null,
}

describe('DashboardDataCard', () => {
  beforeEach(() => {
    get.mockReset()
    post.mockReset()
    toastError.mockReset()
    state.canRebuild = true
  })

  it('shows the status and requests a rebuild', async () => {
    get.mockResolvedValue(built)
    post.mockResolvedValue({ ...built, pending: true, next_rebuild_at: '2026-10-18T16:00:00Z' })
    render(<DashboardDataCard />)
    const button = await screen.findByRole('button', { name: 'Rebuild dashboard data' })
    expect(screen.getByText('Kept up to date automatically.')).toBeTruthy()
    expect(screen.getByText('3')).toBeTruthy()
    await userEvent.setup().click(button)
    expect(post).toHaveBeenCalledWith('/api/v1/dashboard-data/rebuild')
    await waitFor(() => expect(screen.getByText(/starts within a few minutes/)).toBeTruthy())
    expect(
      (screen.getByRole('button', { name: 'Rebuild dashboard data' }) as HTMLButtonElement).disabled
    ).toBe(true)
  })

  it('disables the button within the hour', async () => {
    get.mockResolvedValue({
      ...built,
      rebuild_requested_at: '2026-10-18T15:00:00Z',
      next_rebuild_at: '2026-10-18T16:00:00Z',
    })
    render(<DashboardDataCard />)
    const button = await screen.findByRole('button', { name: 'Rebuild dashboard data' })
    expect((button as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText(/Next rebuild possible at/)).toBeTruthy()
  })

  it('explains a refused request', async () => {
    get.mockResolvedValue(built)
    post.mockRejectedValue(new ApiClientError('too many', 'TOO_MANY_REQUESTS', 429))
    render(<DashboardDataCard />)
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Rebuild dashboard data' }))
    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith('Dashboard data can be rebuilt once per hour.')
    )
  })

  it('hides the action without the permission', async () => {
    state.canRebuild = false
    get.mockResolvedValue(built)
    render(<DashboardDataCard />)
    await screen.findByText('Kept up to date automatically.')
    expect(screen.queryByRole('button', { name: 'Rebuild dashboard data' })).toBeNull()
  })

  it('shows an error state instead of empty numbers', async () => {
    get.mockRejectedValue(new Error('boom'))
    render(<DashboardDataCard />)
    expect(await screen.findByText('Could not load dashboard data status')).toBeTruthy()
  })
})
