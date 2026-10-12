/**
 * The New Scan preview asks the scope gate (POST /scope/check, debounced)
 * about every target and shows refused ones with their fixes; a quick scan
 * refused on start shows the same rows.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ scopeRead: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  const can = (p: string) => p !== actual.Permission.ScopeRead || perms.scopeRead
  return { ...actual, useHasPermission: can, usePermissions: () => ({ can }) }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const { ScopePreview } = await import('../scope-preview')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

beforeEach(() => {
  api.post.mockReset()
  api.get.mockReset().mockResolvedValue({})
  perms.scopeRead = true
})

describe('ScopePreview', () => {
  it('checks the targets once typing settles and lists the refused ones with fixes', async () => {
    api.post.mockResolvedValue({
      results: [
        {
          target: 'app.acme.io',
          allowed: true,
          via: { kind: 'scope_target', pattern: '*.acme.io' },
        },
        {
          target: 'promo.net',
          allowed: false,
          code: 'no_entry',
          fixes: [
            { action: 'request_access', pattern: 'promo.net', target_type: 'domain', days: 7 },
          ],
        },
      ],
    })
    wrap(<ScopePreview targets={['app.acme.io', 'promo.net']} sensorPreference="platform" />)
    expect(await screen.findByText('1 of 2 targets may not be scanned')).toBeInTheDocument()
    expect(api.post).toHaveBeenCalledTimes(1)
    expect(api.post).toHaveBeenCalledWith('/api/v1/scope/check', {
      sensor_preference: 'platform',
      tier: undefined,
      targets: ['app.acme.io', 'promo.net'],
    })
    expect(screen.getByText('Not in scope')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Request access' })).toBeInTheDocument()
    // Allowed rows are folded while something is refused.
    expect(screen.queryByText('Allowed by *.acme.io')).not.toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Show 1 allowed' }))
    expect(screen.getByText('Allowed by *.acme.io')).toBeInTheDocument()
  })

  it('says when everything is in scope', async () => {
    api.post.mockResolvedValue({ results: [{ target: 'a.acme.io', allowed: true }] })
    wrap(<ScopePreview targets={['a.acme.io']} />)
    expect(await screen.findByText('All 1 target is in scope')).toBeInTheDocument()
  })

  it('asks nothing without scope:read', async () => {
    perms.scopeRead = false
    const { container } = wrap(<ScopePreview targets={['a.acme.io']} />)
    await new Promise((r) => setTimeout(r, 500))
    expect(api.post).not.toHaveBeenCalled()
    expect(container).toBeEmptyDOMElement()
  })

  it('splits more than 200 targets into batches', async () => {
    api.post.mockResolvedValue({ results: [] })
    const many = Array.from({ length: 250 }, (_, i) => `h${i}.acme.io`)
    wrap(<ScopePreview targets={many} />)
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(2))
    expect(api.post.mock.calls[0][1].targets).toHaveLength(200)
    expect(api.post.mock.calls[1][1].targets).toHaveLength(50)
  })
})
