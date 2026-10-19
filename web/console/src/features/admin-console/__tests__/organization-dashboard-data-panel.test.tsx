import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AdminApiError } from '@console/lib/admin-api/client'
import type { AdminDashboardDataStatus } from '../api/use-admin-dashboard-data'

const state = vi.hoisted(() => ({
  data: undefined as AdminDashboardDataStatus | undefined,
  rebuild: vi.fn(),
  mutate: vi.fn(),
  toastError: vi.fn(),
}))
vi.mock('../api/use-admin-dashboard-data', () => ({
  useDashboardDataStatus: () => ({
    data: state.data,
    error: undefined,
    isLoading: false,
    mutate: state.mutate,
  }),
  rebuildDashboardData: (...a: unknown[]) => state.rebuild(...a),
}))
vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: (...a: unknown[]) => state.toastError(...a) },
}))

import { OrganizationDashboardDataPanel } from '../components/organization-dashboard-data-panel'

const status: AdminDashboardDataStatus = {
  rebuilt_at: '2026-10-18T02:00:00Z',
  reconciled_at: '2026-10-18T02:00:00Z',
  last_drift: 4,
  rebuild_requested_at: null,
  pending: false,
  queue_depth: 0,
  next_rebuild_at: null,
}

describe('OrganizationDashboardDataPanel', () => {
  beforeEach(() => {
    state.data = status
    state.rebuild.mockReset()
    state.mutate.mockReset()
    state.toastError.mockReset()
  })

  it('shows drift and rebuilds the path organization', async () => {
    state.rebuild.mockResolvedValue({ ...status, pending: true })
    render(<OrganizationDashboardDataPanel tenantId="t-1" canRebuild />)
    expect(screen.getByText('4')).toBeTruthy()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Rebuild dashboard data' }))
    expect(state.rebuild).toHaveBeenCalledWith('t-1')
  })

  it('explains the hourly limit', async () => {
    state.rebuild.mockRejectedValue(new AdminApiError('too many', 429))
    render(<OrganizationDashboardDataPanel tenantId="t-1" canRebuild />)
    await userEvent.setup().click(screen.getByRole('button', { name: 'Rebuild dashboard data' }))
    await waitFor(() =>
      expect(state.toastError).toHaveBeenCalledWith('Dashboard data can be rebuilt once per hour.')
    )
  })

  it('read-only administrators see the status only', () => {
    render(<OrganizationDashboardDataPanel tenantId="t-1" canRebuild={false} />)
    expect(screen.queryByRole('button', { name: 'Rebuild dashboard data' })).toBeNull()
  })
})
