/**
 * The Scope page's provider addresses card: shown only when there is
 * something to decide, one row per provider with "Move to out of scope"
 * (previewed, nothing sent before the confirmation) and "Keep scanning",
 * the person-confirmed addresses under their provider, and no actions
 * without scope:write.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
const perms = vi.hoisted(() => ({ write: true }))
vi.mock('@/lib/api/client', () => api)
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    useHasPermission: () => perms.write,
    usePermissions: () => ({ can: () => perms.write, isOwner: () => false }),
  }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

const { ScopeProviderAddressesCard } = await import('../scope-provider-addresses-card')

const entry = (id: string, pattern: string) => ({
  id,
  pattern,
  target_type: 'ip_address',
  origin: 'import',
  status: 'active',
  created_at: '2026-11-04T14:00:00Z',
})

const card = {
  dataset_version: '2026-11-19.1',
  holding: false,
  groups: [
    {
      provider: 'Microsoft 365',
      class: 'cloud_shared',
      entry_count: 2,
      entries: [entry('e1', '192.0.2.10'), entry('e2', '192.0.2.11')],
      confirmed: [{ asset_id: '0b7f6a52-4c3e-4a8e-9a55-6f2a1c9e0d11', name: '192.0.2.20' }],
    },
  ],
}

beforeEach(() => {
  perms.write = true
  api.get.mockReset().mockResolvedValue(card)
  api.post.mockReset().mockImplementation((_url: string, body: { preview?: boolean }) =>
    Promise.resolve({
      provider: 'Microsoft 365',
      preview: !!body?.preview,
      entries: 2,
      exclusions: 2,
      existing: 0,
      entry_ids: ['e1', 'e2'],
      exclusion_ids: ['x1', 'x2'],
      kept: [],
    })
  )
})

const wrap = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <ScopeProviderAddressesCard />
    </SWRConfig>
  )

describe('provider addresses card', () => {
  it('names the provider and the count, and lists the confirmed addresses', async () => {
    wrap()
    expect(
      await screen.findByText('2 scope entries are Microsoft 365 shared addresses')
    ).toBeInTheDocument()
    const confirmed = screen.getByTestId('scope-provider-confirmed')
    expect(confirmed).toHaveTextContent('Confirmed by a person: keep or move')
    expect(within(confirmed).getByRole('link', { name: '192.0.2.20' })).toBeInTheDocument()
    expect(screen.queryByTestId('scope-provider-holding')).not.toBeInTheDocument()
  })

  it('previews the move and sends it only after the confirmation', async () => {
    wrap()
    await userEvent.click(await screen.findByRole('button', { name: 'Move to out of scope' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Move Microsoft 365 addresses out of scope?')
    expect(dialog).toHaveTextContent('2 entries become exclusions')
    expect(dialog).toHaveTextContent('Names that point at them stay in scope')
    expect(api.post).toHaveBeenCalledTimes(1)
    expect(api.post.mock.calls[0][0]).toBe('/api/v1/scope/provider-addresses/move')
    expect(api.post.mock.calls[0][1]).toEqual({ provider: 'Microsoft 365', preview: true })
    await userEvent.click(within(dialog).getByRole('button', { name: 'Move to out of scope' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(2))
    expect(api.post.mock.calls[1][1]).toEqual({ provider: 'Microsoft 365', preview: false })
  })

  it('keep scanning asks first, then sends the keep', async () => {
    wrap()
    await userEvent.click(await screen.findByRole('button', { name: 'Keep scanning' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Keep scanning Microsoft 365 addresses?')
    expect(api.post).not.toHaveBeenCalled()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Keep scanning' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1))
    expect(api.post.mock.calls[0][0]).toBe('/api/v1/scope/provider-addresses/keep')
    expect(api.post.mock.calls[0][1]).toEqual({ provider: 'Microsoft 365' })
  })

  it('shows the entries on demand', async () => {
    wrap()
    await userEvent.click(await screen.findByRole('button', { name: 'Show entries' }))
    const list = screen.getByRole('list', { name: 'Scope entries of Microsoft 365' })
    expect(within(list).getByText('192.0.2.10')).toBeInTheDocument()
    expect(within(list).getByText('192.0.2.11')).toBeInTheDocument()
  })

  it('hides the actions without scope:write', async () => {
    perms.write = false
    wrap()
    expect(
      await screen.findByText('2 scope entries are Microsoft 365 shared addresses')
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Move to out of scope' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Keep scanning' })).not.toBeInTheDocument()
  })

  it('says the entries are on hold when the organization holds them', async () => {
    api.get.mockResolvedValue({ ...card, holding: true })
    wrap()
    expect(await screen.findByTestId('scope-provider-holding')).toHaveTextContent(
      'Scanning of these addresses is paused'
    )
  })

  it('renders nothing when there is nothing to decide', async () => {
    api.get.mockResolvedValue({ dataset_version: '2026-11-19.1', holding: false, groups: [] })
    const { container } = wrap()
    await waitFor(() => expect(api.get).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
  })
})
