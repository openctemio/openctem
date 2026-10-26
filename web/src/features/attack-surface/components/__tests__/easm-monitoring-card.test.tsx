/**
 * Monitoring card (research/22 P0-11): shows the switches and freshness,
 * saves a switch with the other values unchanged, runs now, and offers no
 * changes without the permissions.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
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
    useCanMutate: (key: string) => (key === 'PUT /api/v1/easm/settings' ? perms.settings : true),
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
  enrichment_enabled: true,
  enrichment_available: true,
  lookalike_ct_enabled: true,
  network_lookups_enabled: true,
  weekly_digest_enabled: true,
  digest_weekday: 1,
  digest_hour_utc: 8,
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
  it('turns lookalike certificate checks off with only that field changed', async () => {
    wrap(<EASMMonitoringCard />)
    const sw = await screen.findByRole('switch', {
      name: 'Certificate checks of lookalike domains',
    })
    expect(sw).toBeChecked()
    await userEvent.click(sw)
    expect(api.put).toHaveBeenCalledWith('/api/v1/easm/settings', {
      ct_enabled: true,
      dns_checks_enabled: true,
      ct_interval_hours: 0,
      dns_interval_hours: 12,
      lookalike_ct_enabled: false,
    })
  })

  it('turns network seed lookups off with only that field changed', async () => {
    wrap(<EASMMonitoringCard />)
    const sw = await screen.findByRole('switch', { name: 'Network seed lookups' })
    await userEvent.click(sw)
    expect(api.put).toHaveBeenCalledWith('/api/v1/easm/settings', {
      ct_enabled: true,
      dns_checks_enabled: true,
      ct_interval_hours: 0,
      dns_interval_hours: 12,
      network_lookups_enabled: !settings.network_lookups_enabled,
    })
  })

  it('turns screenshots on with only that field changed', async () => {
    wrap(<EASMMonitoringCard />)
    const shots = await screen.findByRole('switch', { name: 'Screenshots of web assets' })
    expect(shots).not.toBeChecked()
    await userEvent.click(shots)
    // Turning it on starts screenshots of the web assets, so it asks first.
    expect(api.put).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Keep screenshots' }))
    expect(api.put).toHaveBeenCalledWith('/api/v1/easm/settings', {
      ct_enabled: true,
      dns_checks_enabled: true,
      ct_interval_hours: 0,
      dns_interval_hours: 12,
      web_screenshots_enabled: true,
    })
  })

  it('turns the weekly digest off with only that field changed', async () => {
    wrap(<EASMMonitoringCard />)
    const digest = await screen.findByRole('switch', { name: 'Weekly digest' })
    expect(digest).toBeChecked()
    await userEvent.click(digest)
    expect(api.put).toHaveBeenCalledWith('/api/v1/easm/settings', {
      ct_enabled: true,
      dns_checks_enabled: true,
      ct_interval_hours: 0,
      dns_interval_hours: 12,
      weekly_digest_enabled: false,
    })
  })

  it('cannot change the digest without settings:write', async () => {
    perms.settings = false
    wrap(<EASMMonitoringCard />)
    expect(await screen.findByRole('switch', { name: 'Weekly digest' })).toBeDisabled()
  })

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

  it('turns automatic enrichment off with only that field changed', async () => {
    wrap(<EASMMonitoringCard />)
    const sw = await screen.findByRole('switch', { name: 'Automatic enrichment' })
    expect(sw).toBeChecked()
    await userEvent.click(sw)
    expect(api.put).toHaveBeenCalledWith('/api/v1/easm/settings', {
      ct_enabled: true,
      dns_checks_enabled: true,
      ct_interval_hours: 0,
      dns_interval_hours: 12,
      enrichment_enabled: false,
    })
  })

  it('cannot change automatic enrichment when the platform turned it off', async () => {
    api.get.mockResolvedValue({ ...settings, enrichment_available: false })
    wrap(<EASMMonitoringCard />)
    expect(await screen.findByRole('switch', { name: 'Automatic enrichment' })).toBeDisabled()
    expect(
      screen.getByText('Turned off for the whole platform by the operator.')
    ).toBeInTheDocument()
  })

  it('runs now', async () => {
    wrap(<EASMMonitoringCard />)
    await userEvent.click(await screen.findByRole('button', { name: /Run now/ }))
    // The sweep sends lookups at once, so it asks first.
    expect(api.post).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Run now' }))
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

describe('turning a lookup off', () => {
  it('stays one click and opens no dialog', async () => {
    api.put.mockResolvedValue(settings)
    wrap(<EASMMonitoringCard />)
    const sw = await screen.findByRole('switch', { name: 'Automatic enrichment' })
    expect(sw).toBeChecked()
    await userEvent.click(sw)
    expect(screen.queryByRole('alertdialog')).toBeNull()
  })
})
