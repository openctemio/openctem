import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import type { WebEndpointParamResponse, WebEndpointResponse } from '@/lib/api/generated'

const state: {
  endpoint?: WebEndpointResponse
  params?: WebEndpointParamResponse[]
  canWrite: boolean
} = { canWrite: true }

vi.mock('../api/use-web-surface', () => ({
  useWebEndpoint: () => ({ data: state.endpoint, isLoading: false, mutate: vi.fn() }),
  useWebEndpointParams: () => ({ data: { data: state.params }, isLoading: false }),
  updateWebEndpoint: vi.fn(),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => state.canWrite,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

import { EndpointSheet } from '../components/endpoint-sheet'

const base: WebEndpointResponse = {
  id: 'ep-1',
  origin_asset_id: 'asset-1',
  origin: 'https://shop.example.com',
  method: 'POST',
  path_template: '/admin/users/{int}',
  example_path: '/admin/users/42',
  kind: 'form',
  auth_state: 'none',
  in_scope: true,
  state: 'active',
  sources: ['js'],
  technologies: [],
  labels: [],
  param_count: 1,
  first_seen_at: new Date().toISOString(),
  last_seen_at: new Date().toISOString(),
}

describe('EndpointSheet', () => {
  beforeEach(() => {
    state.canWrite = true
    state.params = [
      {
        location: 'form',
        name: 'redirect_uri',
        risk_hints: ['ssrf_candidate'],
        sources: ['js'],
        required: false,
      },
    ]
  })

  it('shows the endpoint as text, its parameter names and no values', () => {
    state.endpoint = base
    render(<EndpointSheet endpointId="ep-1" onClose={() => {}} />)
    expect(screen.getByText('/admin/users/{int}')).toBeInTheDocument()
    const list = screen.getByRole('list', { name: 'Parameters' })
    expect(within(list).getByText('redirect_uri')).toBeInTheDocument()
    expect(within(list).getByText('SSRF candidate')).toBeInTheDocument()
    expect(screen.getByText(/parameter values are never stored/i)).toBeInTheDocument()
    // The path is never a link that fetches it.
    expect(screen.queryByRole('link', { name: /admin\/users/ })).toBeNull()
    expect(screen.queryByText(/never tested/i)).toBeNull()
  })

  it('flags an excluded endpoint as untested and links to the exclusion', () => {
    state.endpoint = { ...base, in_scope: false, exclusion_id: 'ex-1' }
    render(<EndpointSheet endpointId="ep-1" onClose={() => {}} />)
    expect(screen.getByText('Never tested')).toBeInTheDocument()
    expect(screen.getByText(/no findings here does not mean it is safe/i)).toBeInTheDocument()
    const links = screen.getAllByRole('link', { name: /exclusion/i })
    expect(links.every((l) => l.getAttribute('href') === '/scope-config?tab=exclusions')).toBe(true)
  })

  it('offers Ignore only to members who may change assets', () => {
    state.endpoint = base
    state.canWrite = false
    render(<EndpointSheet endpointId="ep-1" onClose={() => {}} />)
    expect(screen.queryByRole('button', { name: /ignore/i })).toBeNull()
  })
})
