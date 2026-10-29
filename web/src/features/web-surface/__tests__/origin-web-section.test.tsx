import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type {
  WebEndpointEventResponse,
  WebEndpointParamResponse,
  WebEndpointResponse,
} from '@/lib/api/generated'

const XSS = '<img src=x onerror=alert(1)>'

const state: {
  endpoints: WebEndpointResponse[]
  events: WebEndpointEventResponse[]
  params: WebEndpointParamResponse[]
} = { endpoints: [], events: [], params: [] }

const list = <T,>(rows: T[]) => ({
  rows,
  total: rows.length,
  error: undefined,
  isLoading: false,
  mutate: vi.fn(),
})

vi.mock('../api/use-web-surface', () => ({
  useWebEndpointStats: () => ({
    data: { total: 3, unauth_sensitive: 1, excluded_untested: 0 },
    isLoading: false,
  }),
  useWebEndpoints: () => list(state.endpoints),
  useWebEndpointEvents: () => list(state.events),
  useWebEndpointsParams: (ids: string[]) => ({
    lists: ids.map(() => state.params),
    isLoading: false,
  }),
  useWebPathCatalog: () => ({ data: { entries: [] } }),
  useWebEndpoint: () => ({ data: undefined, isLoading: false, mutate: vi.fn() }),
  useWebEndpointParams: () => ({ data: { data: [] }, isLoading: false }),
  updateWebEndpoint: vi.fn(),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

import { OriginWebSection } from '../components/origin-web-section'

const endpoint: WebEndpointResponse = {
  id: 'ep-1',
  origin_asset_id: 'a1',
  origin: 'https://shop.example.com',
  method: 'GET',
  path_template: XSS,
  kind: 'page',
  auth_state: 'none',
  in_scope: true,
  state: 'active',
  sources: [],
  technologies: [],
  labels: [],
  param_count: 1,
  first_seen_at: new Date().toISOString(),
  last_seen_at: new Date().toISOString(),
}

function expectInert(container: HTMLElement) {
  expect(container.querySelector('img')).toBeNull()
  expect(container.querySelector('script')).toBeNull()
  expect(container.querySelector('[onerror]')).toBeNull()
}

describe('OriginWebSection', () => {
  beforeEach(() => {
    state.endpoints = [endpoint]
    state.events = [
      {
        id: 'ev-1',
        endpoint_id: 'ep-1',
        kind: 'appeared',
        method: 'GET',
        path_template: XSS,
        origin: 'https://shop.example.com',
        at: new Date().toISOString(),
      },
    ]
    state.params = [{ location: 'query', name: XSS, risk_hints: ['redirect'], sources: ['crawl'] }]
  })

  it('shows a clear empty state when http_posture is absent', () => {
    render(<OriginWebSection assetId="a1" assetName="https://shop.example.com" properties={{}} />)
    expect(screen.getByText('No header data yet')).toBeInTheDocument()
  })

  it('lists present and missing headers and cookie flags as inert text', () => {
    const { container } = render(
      <OriginWebSection
        assetId="a1"
        assetName="javascript:alert(1)"
        properties={{
          http_posture: {
            headers: ['hsts'],
            cookies: [{ name: XSS, secure: true, http_only: false }],
          },
        }}
      />
    )
    const list = screen.getByRole('list', { name: 'Security headers' })
    expect(within(list).getByText(/Strict-Transport-Security: Present/)).toBeInTheDocument()
    expect(within(list).getByText(/Content-Security-Policy: Missing/)).toBeInTheDocument()
    expect(screen.getByText(XSS)).toBeInTheDocument()
    expectInert(container)
    // A non-http name is never a link.
    expect(screen.queryByRole('link')).toBeNull()
  })

  it('links an http(s) origin with a safe rel only', () => {
    render(<OriginWebSection assetId="a1" assetName="https://shop.example.com" properties={{}} />)
    const link = screen.getByRole('link', { name: 'https://shop.example.com' })
    expect(link.getAttribute('rel')).toBe('noopener noreferrer nofollow')
  })

  it('Endpoints tab renders a hostile path as text, not a link or HTML', async () => {
    const { container } = render(<OriginWebSection assetId="a1" properties={{}} />)
    await userEvent.click(screen.getByRole('tab', { name: 'Endpoints' }))
    expect(screen.getAllByText(XSS).length).toBeGreaterThan(0)
    expectInert(container)
    expect(screen.queryByRole('link', { name: /img/ })).toBeNull()
    expect(screen.getByRole('button', { name: /export csv/i })).toBeInTheDocument()
  })

  it('Parameters tab flattens parameters and renders names as text', async () => {
    const { container } = render(<OriginWebSection assetId="a1" properties={{}} />)
    await userEvent.click(screen.getByRole('tab', { name: 'Parameters' }))
    expect(screen.getAllByText(XSS).length).toBeGreaterThan(0)
    expect(screen.getByText('Open redirect candidate')).toBeInTheDocument()
    expectInert(container)
  })

  it('Changes tab renders events as text', async () => {
    const { container } = render(<OriginWebSection assetId="a1" properties={{}} />)
    await userEvent.click(screen.getByRole('tab', { name: 'Changes' }))
    expect(screen.getByText('Appeared')).toBeInTheDocument()
    expect(screen.getAllByText(XSS).length).toBeGreaterThan(0)
    expectInert(container)
  })
})
