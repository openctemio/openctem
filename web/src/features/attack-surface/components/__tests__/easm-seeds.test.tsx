/**
 * Boundaries › Seeds: lists the server's seeds with their verification,
 * adds a root domain only after the attestation box is ticked (and always
 * sends attested: true), and offers no changes without scope:write.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ write: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    usePermissions: () => ({
      can: (p: string) =>
        (p !== actual.Permission.ScopeWrite && p !== actual.Permission.ScopeDelete) || perms.write,
    }),
  }
})
const modules = vi.hoisted(() => ({ ids: ['attack_surface'] }))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ moduleIds: modules.ids, isLoading: false }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const { EASMSeedsPanel } = await import('../easm-seeds')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const seeds = {
  data: [
    {
      id: 's1',
      kind: 'root_domain',
      value: 'acme.com',
      label: 'Main brand',
      discovery_enabled: true,
      verification: 'dns_txt',
      verified_domain: 'acme.com',
      attested_at: '2026-10-01T00:00:00Z',
      created_at: '2026-10-01T00:00:00Z',
    },
    {
      id: 's2',
      kind: 'root_domain',
      value: 'acme.io',
      discovery_enabled: false,
      verification: 'none',
      attested_at: '2026-10-01T00:00:00Z',
      created_at: '2026-10-01T00:00:00Z',
    },
  ],
}

beforeEach(() => {
  api.get.mockReset()
  api.post.mockReset()
  perms.write = true
  modules.ids = ['attack_surface']
})

describe('EASMSeedsPanel', () => {
  it('lists the seeds with their verification', async () => {
    api.get.mockResolvedValue(seeds)
    wrap(<EASMSeedsPanel />)
    expect(await screen.findByText('acme.com')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/v1/easm/seeds')
    expect(screen.getByText(/Verified \(acme\.com\)/)).toBeInTheDocument()
    expect(screen.getByText('Asserted, not verified')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Discovery from acme.io' })).not.toBeChecked()
  })

  it('adds a root domain only after the attestation', async () => {
    api.get.mockResolvedValue(seeds)
    api.post.mockResolvedValue({ id: 's3', kind: 'root_domain', value: 'acme.org' })
    const user = userEvent.setup()
    wrap(<EASMSeedsPanel />)
    await screen.findByText('acme.com')
    await user.click(screen.getByRole('button', { name: /Add seed/ }))
    await user.type(screen.getByLabelText('Root domain'), 'acme.org')
    const submit = screen.getAllByRole('button', { name: 'Add seed' }).at(-1)!
    expect(submit).toBeDisabled()
    await user.click(screen.getByRole('checkbox'))
    await user.click(submit)
    expect(api.post).toHaveBeenCalledWith('/api/v1/easm/seeds', {
      kind: 'root_domain',
      value: 'acme.org',
      attested: true,
    })
  })

  it('offers no changes without scope:write', async () => {
    perms.write = false
    api.get.mockResolvedValue(seeds)
    wrap(<EASMSeedsPanel />)
    await screen.findByText('acme.com')
    expect(screen.queryByRole('button', { name: /Add seed/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Remove/ })).toBeNull()
    expect(screen.getByRole('switch', { name: 'Discovery from acme.com' })).toBeDisabled()
  })

  it('does not call the API when the Attack surface module is off', () => {
    modules.ids = []
    wrap(<EASMSeedsPanel />)
    expect(api.get).not.toHaveBeenCalled()
    expect(screen.getByText(/not enabled/)).toBeInTheDocument()
  })
})
