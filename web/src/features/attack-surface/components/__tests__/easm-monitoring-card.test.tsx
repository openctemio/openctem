/**
 * Monitoring card (research/22 P0-11): shows the switches and freshness,
 * saves a switch with the other values unchanged, runs now, and offers no
 * changes without the permissions.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ settings: true, run: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    usePermissions: () => ({
      can: (p: string) =>
        p === actual.Permission.SettingsWrite
          ? perms.settings
          : p === actual.Permission.ScopeWrite
            ? perms.run
            : true,
    }),
  }
})
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ moduleIds: ['attack_surface'], isLoading: false }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const { EASMMonitoringCard } = await import('../easm-monitoring-card')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const settings = {
  ct_enabled: true,
  dns_checks_enabled: true,
  ct_interval_hours: 0,
  dns_interval_hours: 12,
  ct_effective_interval_hours: 24,
  dns_effective_interval_hours: 12,
  min_interval_hours: 6,
  max_interval_hours: 168,
  ct_available: true,
  dns_available: true,
  last_ct_sweep_at: '2026-10-05T01:00:00Z',
}

beforeEach(() => {
  api.get.mockReset().mockResolvedValue(settings)
  api.put
    .mockReset()
    .mockImplementation((_u: string, body: object) => Promise.resolve({ ...settings, ...body }))
  api.post.mockReset().mockResolvedValue({ started_at: '2026-10-05T02:00:00Z' })
  perms.settings = true
  perms.run = true
})

describe('EASMMonitoringCard', () => {
  it('turns CT off keeping the other settings', async () => {
    wrap(<EASMMonitoringCard />)
    const ct = await screen.findByRole('switch', { name: 'Certificate Transparency discovery' })
    expect(ct).toBeChecked()
    await userEvent.click(ct)
    expect(api.put).toHaveBeenCalledWith('/api/v1/easm/settings', {
      ct_enabled: false,
      dns_checks_enabled: true,
      ct_interval_hours: 0,
      dns_interval_hours: 12,
    })
  })

  it('runs now', async () => {
    wrap(<EASMMonitoringCard />)
    await userEvent.click(await screen.findByRole('button', { name: /Run now/ }))
    expect(api.post).toHaveBeenCalledWith('/api/v1/easm/sweeps', {})
  })

  it('disables run now inside the 15-minute window', async () => {
    api.get.mockResolvedValue({
      ...settings,
      run_now_available_at: new Date(Date.now() + 600_000).toISOString(),
    })
    wrap(<EASMMonitoringCard />)
    expect(await screen.findByRole('button', { name: /Run now/ })).toBeDisabled()
  })

  it('offers no changes without the permissions', async () => {
    perms.settings = false
    perms.run = false
    wrap(<EASMMonitoringCard />)
    expect(await screen.findByRole('switch', { name: 'DNS checks' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: /Run now/ })).not.toBeInTheDocument()
  })
})
