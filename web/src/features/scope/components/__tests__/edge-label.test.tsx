/**
 * The edge label (research/259, owner decision 2026-10-30): a quiet chip on a
 * name served through a provider; on the provider's own address, with scope
 * write, a one-click "Add to out of scope" behind a confirm dialog that says
 * why and what else it stops, then one bulk Do not scan exclusion.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ write: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    useHasPermission: (p: string) => p !== actual.Permission.ScopeWrite || perms.write,
  }
})
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

// Radix measures the dialog and tooltip.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const { EdgeLabel, edgeExclusionItem } = await import('../edge-label')
const { TooltipProvider } = await import('@/components/ui/tooltip')

const wrap = (ui: React.ReactNode) => render(<TooltipProvider>{ui}</TooltipProvider>)

beforeEach(() => {
  api.post.mockReset()
  toast.success.mockReset()
  toast.error.mockReset()
  perms.write = true
})

describe('EdgeLabel', () => {
  it('a name served through a provider: "Behind <provider>", no action', () => {
    wrap(<EdgeLabel edge={{ class: 'edge', provider: 'Cloudflare' }} />)
    expect(screen.getByText('Behind Cloudflare')).toBeInTheDocument()
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('an edge address adds a Do not scan exclusion after the confirm dialog', async () => {
    api.post.mockResolvedValue({
      results: [
        {
          exclusion_type: 'ip_address',
          pattern: '104.16.1.1',
          result: 'created',
          status: 'active',
          id: 'x',
        },
      ],
      created: 1,
      existing: 0,
      refused: 0,
    })
    const onExcluded = vi.fn()
    const rowClick = vi.fn()
    wrap(
      // A table row opens its drawer on click; the chip must not.
      <div onClick={rowClick}>
        <EdgeLabel
          edge={{ class: 'edge', provider: 'Cloudflare', address: '104.16.1.1' }}
          onExcluded={onExcluded}
        />
      </div>
    )
    await userEvent.click(
      screen.getByRole('button', { name: 'Cloudflare edge: add to out of scope' })
    )
    expect(rowClick).not.toHaveBeenCalled()
    expect(screen.getByText('Add 104.16.1.1 to out of scope?')).toBeInTheDocument()
    expect(screen.getByText(/Scanning it tests Cloudflare, not your systems/)).toBeInTheDocument()
    expect(screen.getByTestId('edge-exclude-names')).toHaveTextContent(
      /Names that resolve to this address are left out of scans as well/
    )
    expect(api.post).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Add to out of scope' }))
    await waitFor(() => expect(onExcluded).toHaveBeenCalled())
    expect(api.post).toHaveBeenCalledTimes(1)
    expect(api.post).toHaveBeenCalledWith('/api/v1/scope/exclusions/bulk', {
      items: [{ exclusion_type: 'ip_address', pattern: '104.16.1.1' }],
      reason: 'Shared Cloudflare address: scanning it tests the provider',
      kind: 'do_not_scan',
    })
    expect(toast.success).toHaveBeenCalledWith('104.16.1.1 is out of scope: no scan will reach it')
  })

  it('cancel sends nothing', async () => {
    wrap(<EdgeLabel edge={{ class: 'edge', provider: 'Fastly', address: '151.101.1.1' }} />)
    await userEvent.click(screen.getByRole('button', { name: 'Fastly edge: add to out of scope' }))
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(api.post).not.toHaveBeenCalled()
  })

  it('a pending exclusion (Strict approval) says it waits', async () => {
    api.post.mockResolvedValue({
      results: [
        {
          exclusion_type: 'ip_address',
          pattern: '104.16.1.1',
          result: 'created',
          status: 'pending',
          id: 'x',
        },
      ],
      created: 1,
      existing: 0,
      refused: 0,
    })
    wrap(<EdgeLabel edge={{ class: 'edge', provider: 'Cloudflare', address: '104.16.1.1' }} />)
    await userEvent.click(screen.getByRole('button', { name: /add to out of scope/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Add to out of scope' }))
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith(
        '104.16.1.1 waits for an exclusion approver before scans leave it out'
      )
    )
  })

  it('without scope write, or already excluded, the address is a label only', () => {
    perms.write = false
    const { unmount } = wrap(
      <EdgeLabel edge={{ class: 'edge', provider: 'Cloudflare', address: '104.16.1.1' }} />
    )
    expect(screen.getByText('Cloudflare edge')).toBeInTheDocument()
    expect(screen.queryByRole('button')).toBeNull()
    unmount()
    perms.write = true
    wrap(
      <EdgeLabel
        edge={{ class: 'saas_hosting', provider: 'GitHub', address: '198.51.100.6' }}
        excluded
      />
    )
    expect(screen.getByText('GitHub hosting')).toBeInTheDocument()
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('maps a range or CIDR entry to its exclusion kind', () => {
    expect(edgeExclusionItem('104.16.1.0/24')).toEqual({
      exclusion_type: 'cidr',
      pattern: '104.16.1.0/24',
    })
    expect(edgeExclusionItem('104.16.1.1-104.16.1.9')).toEqual({
      exclusion_type: 'ip_range',
      pattern: '104.16.1.1-104.16.1.9',
    })
    expect(edgeExclusionItem(' 2606:4700::1 ')).toEqual({
      exclusion_type: 'ip_address',
      pattern: '2606:4700::1',
    })
  })
})
