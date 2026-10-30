/**
 * Ports on resolved addresses: each open port with its address, service and
 * last seen; the count of ports outside the caller's data scope, never their
 * rows; an empty state; a refused read hides the section; nothing is fetched
 * without assets:read.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import { ResolvedPortsSection, hasResolvedPorts } from '../resolved-ports-section'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const api = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

let perms: string[] = []
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: (p: string) => perms.includes(p) }) }
})

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

beforeEach(() => {
  api.get.mockReset()
  perms = ['assets:read']
})

describe('ResolvedPortsSection', () => {
  it('lists each port with its address and service, and counts hidden ones', async () => {
    api.get.mockResolvedValue({
      items: [
        {
          address_id: 'ip1',
          address: '203.0.113.10',
          port_id: 'p1',
          port: 8443,
          transport: 'tcp',
          service: 'https',
          product: 'nginx',
          version: '1.25',
          last_seen: '2026-10-29T10:00:00Z',
        },
      ],
      hidden_count: 2,
      truncated: false,
    })
    wrap(<ResolvedPortsSection assetId="a1" />)
    expect(await screen.findAllByText('203.0.113.10')).not.toHaveLength(0)
    expect(api.get).toHaveBeenCalledWith('/api/v1/assets/a1/resolved-ports')
    expect(screen.getAllByText('8443/tcp')[0].closest('a')).toHaveAttribute('href', '/assets/p1')
    expect(screen.getAllByText('203.0.113.10')[0].closest('a')).toHaveAttribute(
      'href',
      '/assets/ip1'
    )
    expect(screen.getAllByText('nginx 1.25').length).toBeGreaterThan(0)
    expect(screen.getByText(/2 more ports are on addresses or ports outside/)).toBeInTheDocument()
  })

  it('says so when no port is on record', async () => {
    api.get.mockResolvedValue({ items: [], hidden_count: 0, truncated: false })
    wrap(<ResolvedPortsSection assetId="a1" />)
    expect(await screen.findByText('No open ports on record')).toBeInTheDocument()
  })

  it('a refused read hides the section', async () => {
    api.get.mockRejectedValue(Object.assign(new Error('nope'), { statusCode: 404 }))
    const { container } = wrap(<ResolvedPortsSection assetId="a1" />)
    await waitFor(() => expect(api.get).toHaveBeenCalled())
    await waitFor(() => expect(container).toBeEmptyDOMElement())
  })

  it('fetches nothing without assets:read', () => {
    perms = []
    wrap(<ResolvedPortsSection assetId="a1" />)
    expect(api.get).not.toHaveBeenCalled()
  })

  it('applies to names only', () => {
    expect(hasResolvedPorts('domain')).toBe(true)
    expect(hasResolvedPorts('subdomain')).toBe(true)
    expect(hasResolvedPorts('ip_address')).toBe(false)
  })
})
