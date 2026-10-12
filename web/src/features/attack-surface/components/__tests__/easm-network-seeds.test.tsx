/**
 * Scoping › Networks (RFC-082): seeds with their announced prefixes, the
 * guardrails' verdict per prefix, the shared-network notice, adding a seed,
 * and no changes without scope:write.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ write: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    usePermissions: () => ({
      can: (p: string) =>
        p === actual.Permission.ScopeWrite || p === actual.Permission.ScopeDelete
          ? perms.write
          : true,
    }),
  }
})
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ moduleIds: ['attack_surface'], isLoading: false }),
}))
vi.mock('@/features/scope/components/scope-check-results', () => ({
  ScopeFixButtons: ({ fixes }: { fixes: { pattern: string }[] }) => (
    <button type="button">add {fixes[0].pattern}</button>
  ),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const { EASMNetworkSeedsPanel } = await import('../easm-network-seeds')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const list = {
  max: 50,
  items: [
    {
      id: 's1',
      kind: 'asn',
      value: 'AS3333',
      holder: 'RIPE-NCC-AS',
      last_expanded_at: '2026-10-10T00:00:00Z',
      prefixes: ['193.0.10.0/23', '10.0.0.0/8'],
      prefix_suggestions: [
        { prefix: '193.0.10.0/23', allowed: true },
        { prefix: '203.0.0.0/8', allowed: false, refusal: 'CIDR_TOO_LARGE' },
      ],
      suggestions: [],
    },
    {
      id: 's2',
      kind: 'asn',
      value: 'AS16509',
      holder: 'AMAZON-02',
      shared: true,
      last_expanded_at: '2026-10-10T00:00:00Z',
      prefix_suggestions: [],
      suggestions: [],
    },
    {
      id: 's3',
      kind: 'org_name',
      value: 'Examplecorp',
      last_expanded_at: '2026-10-10T00:00:00Z',
      prefix_suggestions: [],
      suggestions: [{ asn: 'AS64501', description: 'EXAMPLECORP-NET' }],
    },
  ],
}

beforeEach(() => {
  api.get.mockReset().mockResolvedValue(list)
  api.post.mockReset().mockResolvedValue({ id: 's4' })
  api.del.mockReset().mockResolvedValue(undefined)
  perms.write = true
})

describe('EASMNetworkSeedsPanel', () => {
  it('lists prefixes with the guardrails verdict and the shared notice', async () => {
    wrap(<EASMNetworkSeedsPanel />)
    expect(await screen.findByText('AS3333')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'add 193.0.10.0/23' })).toBeInTheDocument()
    expect(screen.getByText('Larger than the platform allows')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'add 203.0.0.0/8' })).toBeNull()
    expect(screen.getByText(/belongs to a cloud or CDN provider/)).toBeInTheDocument()
  })

  it('adds an AS seed, and an AS found for an organization', async () => {
    wrap(<EASMNetworkSeedsPanel />)
    await screen.findByText('AS3333')
    await userEvent.type(screen.getByLabelText('Value'), 'AS15169')
    await userEvent.click(screen.getByRole('button', { name: 'Add seed' }))
    expect(api.post).toHaveBeenCalledWith('/api/v1/easm/network-seeds', {
      kind: 'asn',
      value: 'AS15169',
      label: undefined,
    })
    await userEvent.click(screen.getByRole('button', { name: 'Add as AS seed' }))
    expect(api.post).toHaveBeenLastCalledWith('/api/v1/easm/network-seeds', {
      kind: 'asn',
      value: 'AS64501',
      label: undefined,
    })
  })

  it('offers no changes without scope:write', async () => {
    perms.write = false
    wrap(<EASMNetworkSeedsPanel />)
    await screen.findByText('AS3333')
    expect(screen.queryByRole('button', { name: 'Add seed' })).toBeNull()
    expect(screen.queryByRole('button', { name: /^add / })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Remove AS3333' })).toBeNull()
  })
})
