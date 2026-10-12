/**
 * Attack surface › Lookalikes (RFC-083): watches with their counts, adding
 * a watch, triaging a registered lookalike, and no changes without the
 * permissions.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ write: true, triage: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    usePermissions: () => ({
      can: (p: string) => {
        if (p === actual.Permission.ScopeWrite || p === actual.Permission.ScopeDelete)
          return perms.write
        if (p === actual.Permission.ExposuresTriage) return perms.triage
        return true
      },
    }),
  }
})
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ moduleIds: ['attack_surface'], isLoading: false }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const { EASMLookalikes } = await import('../easm-lookalikes')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const watches = {
  max: 20,
  techniques: ['omission', 'tld'],
  items: [
    {
      id: 'w1',
      domain: 'example.com',
      enabled: true,
      techniques: [],
      max_candidates: 300,
      candidates: 120,
      checked: 80,
      registered: 2,
    },
  ],
}
const exposures = {
  data: [
    {
      id: 'x1',
      event_type: 'lookalike_domain',
      severity: 'medium',
      state: 'active',
      title: 'Lookalike domain registered: examp1e.com',
      details: {
        domain: 'examp1e.com',
        display: 'examp1e.com',
        lookalike_of: 'example.com',
        technique: 'omission',
        has_mx: true,
        ct_certificates: 2,
      },
      first_seen_at: '2026-10-10T00:00:00Z',
    },
  ],
  total: 1,
}

beforeEach(() => {
  api.get
    .mockReset()
    .mockImplementation((url: string) =>
      Promise.resolve(url.startsWith('/api/v1/exposures') ? exposures : watches)
    )
  api.post.mockReset().mockResolvedValue({})
  perms.write = true
  perms.triage = true
})

describe('EASMLookalikes', () => {
  it('lists watches and registered lookalikes', async () => {
    wrap(<EASMLookalikes />)
    expect(await screen.findByText('example.com')).toBeInTheDocument()
    expect(screen.getByText('2 registered of 80 checked (120 candidates)')).toBeInTheDocument()
    expect(await screen.findByText('examp1e.com')).toBeInTheDocument()
    expect(screen.getByText('Receives mail')).toBeInTheDocument()
    const url = api.get.mock.calls
      .map((c) => c[0] as string)
      .find((u) => u.startsWith('/api/v1/exposures'))
    expect(url).toContain('event_type=lookalike_domain')
    expect(url).toContain('state=active')
  })

  it('adds a watch with the chosen techniques', async () => {
    wrap(<EASMLookalikes />)
    await screen.findByText('example.com')
    await userEvent.type(screen.getByLabelText('Root domain'), 'example.org')
    await userEvent.click(
      screen.getByLabelText('Other ending (TLD)', { selector: '#new-watch-tld' })
    )
    await userEvent.click(screen.getByRole('button', { name: 'Watch' }))
    expect(api.post).toHaveBeenCalledWith('/api/v1/easm/lookalikes/watches', {
      domain: 'example.org',
      techniques: ['tld'],
      max_candidates: 300,
    })
  })

  it('triages a lookalike as taken down', async () => {
    wrap(<EASMLookalikes />)
    await screen.findByText('examp1e.com')
    await userEvent.click(screen.getByRole('button', { name: 'Taken down' }))
    expect(api.post).toHaveBeenCalledWith(expect.stringContaining('/x1/resolve'), {
      reason: 'Taken down',
    })
  })

  it('offers no changes without the permissions', async () => {
    perms.write = false
    perms.triage = false
    wrap(<EASMLookalikes />)
    await screen.findByText('examp1e.com')
    expect(screen.queryByRole('button', { name: 'Watch' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Taken down' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Stop watching example.com' })).toBeNull()
  })
})
