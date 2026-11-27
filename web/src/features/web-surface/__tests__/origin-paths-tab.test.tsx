import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { WebPathEndpoint, WebPathFolder, WebPathLevel } from '../api/use-web-paths'

const XSS = '<img src=x onerror=alert(1)>'

const state = vi.hoisted(() => ({
  phone: false,
  path: '/',
  setPath: vi.fn(),
  levels: {} as Record<string, unknown>,
  calls: [] as { path: string; options: Record<string, unknown>; filters: unknown }[],
}))

vi.mock('../api/use-web-paths', () => ({
  useWebPaths: (
    _id: string,
    path: string,
    filters: unknown,
    options: Record<string, unknown> = {}
  ) => {
    state.calls.push({ path, options, filters })
    return { data: state.levels[path], error: undefined, isLoading: false, mutate: vi.fn() }
  },
}))
vi.mock('@/hooks/use-mobile', () => ({
  useIsMobile: () => state.phone,
  useIsTablet: () => false,
}))
vi.mock('@/hooks/use-url-param', async (orig) => ({
  ...(await orig<typeof import('@/hooks/use-url-param')>()),
  useUrlFilter: () => [state.path, state.setPath],
}))
vi.mock('../components/endpoint-sheet', () => ({
  EndpointSheet: ({ endpointId }: { endpointId: string | null }) =>
    endpointId ? <div role="dialog">sheet {endpointId}</div> : null,
}))
vi.mock('@/features/scans/components/lazy-dialogs', () => ({
  LazyScanAssetsDialog: ({ open, title }: { open: boolean; title?: string }) =>
    open ? <div role="dialog">{title}</div> : null,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

import { OriginPathsTab } from '../components/origin-paths-tab'

const totals = {
  recorded: 3,
  endpoints: 3,
  hidden: 1,
  out_of_scope: 1,
  findings: 2,
  unrecorded_findings: 0,
  top_severity: 'critical',
  origin_findings: 1,
  capped: false,
}

const folder = (name: string, extra: Partial<WebPathFolder> = {}): WebPathFolder => ({
  name,
  path: `/${name}`,
  param: false,
  endpoints: 2,
  out_of_scope: 0,
  findings: 0,
  has_folders: true,
  ...extra,
})

const endpoint: WebPathEndpoint = {
  id: 'ep-1',
  origin_asset_id: 'a1',
  origin: 'https://shop.example.com',
  method: 'GET',
  path_template: `/api/${XSS}`,
  kind: 'page',
  auth_state: 'none',
  in_scope: false,
  state: 'active',
  sources: [],
  technologies: [],
  labels: [],
  param_count: 0,
  first_seen_at: new Date().toISOString(),
  last_seen_at: new Date().toISOString(),
  finding_count: 2,
  top_severity: 'critical',
}

const level = (over: Partial<WebPathLevel> = {}): WebPathLevel => ({
  path: '/',
  totals,
  folders: [
    folder('api', { findings: 2, top_severity: 'critical' }),
    folder('admin', { out_of_scope: 2 }),
  ],
  folders_truncated: false,
  endpoints: [endpoint],
  endpoint_total: 1,
  page: 1,
  per_page: 50,
  ...over,
})

function expectInert(container: HTMLElement) {
  expect(container.querySelector('img')).toBeNull()
  expect(container.querySelector('[onerror]')).toBeNull()
}

describe('OriginPathsTab', () => {
  beforeEach(() => {
    state.phone = false
    state.path = '/'
    state.setPath = vi.fn()
    state.calls = []
    state.levels = { '/': level() }
  })

  it('shows the tree and the endpoints under the selected path, as text', () => {
    const { container } = render(
      <OriginPathsTab assetId="a1" assetName="https://shop.example.com" canCrawl />
    )
    const tree = screen.getByRole('tree', { name: 'Paths of this site' })
    expect(within(tree).getByText('api')).toBeInTheDocument()
    // An out-of-scope folder stays listed, marked.
    expect(within(tree).getByRole('img', { name: '2 out of scope' })).toBeInTheDocument()
    // A severity dot names the worst finding under the folder.
    expect(within(tree).getAllByRole('img', { name: /critical finding/i }).length).toBeGreaterThan(
      0
    )
    expect(screen.getAllByText(`/api/${XSS}`).length).toBeGreaterThan(0)
    expectInert(container)
    // Desktop: all endpoints below the node, one page; the tree loads its levels without endpoints.
    expect(state.calls.some((c) => c.path === '/' && c.options.perPage === 0)).toBe(true)
    expect(state.calls.some((c) => c.path === '/' && c.options.here === false)).toBe(true)
  })

  it('says what filters hide and shows everything again in one step', async () => {
    render(<OriginPathsTab assetId="a1" assetName="https://shop.example.com" canCrawl={false} />)
    expect(screen.getByText(/1 hidden by filters/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Hide static files/ })).toHaveAttribute(
      'aria-pressed',
      'true'
    )
    await userEvent.click(screen.getByRole('button', { name: 'Show all' }))
    expect(screen.getByRole('button', { name: /Hide static files/ })).toHaveAttribute(
      'aria-pressed',
      'false'
    )
    // Gone endpoints come back too: Show all hides nothing.
    const last = state.calls[state.calls.length - 1]
    expect(last.filters).toMatchObject({ hideStatic: false, includeGone: true, hide4xx: false })
  })

  it('selects a node with the keyboard and moves through the tree', () => {
    render(<OriginPathsTab assetId="a1" assetName="https://shop.example.com" canCrawl={false} />)
    const items = screen.getAllByRole('treeitem')
    expect(items[0]).toHaveAttribute('tabindex', '0')
    items[0].focus()
    fireEvent.keyDown(items[0], { key: 'ArrowDown' })
    expect(document.activeElement).toBe(items[1])
    fireEvent.keyDown(items[1], { key: 'Enter' })
    expect(state.setPath).toHaveBeenCalledWith('/api')
    fireEvent.keyDown(items[1], { key: 'ArrowLeft' })
    expect(document.activeElement).toBe(items[0])
  })

  it('opens the endpoint sheet from a row', async () => {
    render(<OriginPathsTab assetId="a1" assetName="https://shop.example.com" canCrawl={false} />)
    await userEvent.click(screen.getAllByText(`/api/${XSS}`)[0])
    expect(screen.getByRole('dialog')).toHaveTextContent('sheet ep-1')
  })

  it('on a phone lists one level with a breadcrumb back up', async () => {
    state.phone = true
    state.path = '/api'
    state.levels['/api'] = level({
      path: '/api',
      folders: [folder('{int}', { path: '/api/{int}', param: true })],
    })
    render(<OriginPathsTab assetId="a1" assetName="https://shop.example.com" canCrawl={false} />)
    expect(screen.queryByRole('tree')).toBeNull()
    expect(screen.getByTestId('drill-down-breadcrumb')).toBeInTheDocument()
    expect(state.calls.some((c) => c.path === '/api' && c.options.here === true)).toBe(true)
    await userEvent.click(screen.getByRole('button', { name: /Variable segment/ }))
    expect(state.setPath).toHaveBeenCalledWith('/api/{int}')
  })

  it('says a never-crawled site has no paths, with Crawl only when the viewer may scan', async () => {
    state.levels = {
      '/': level({
        totals: { ...totals, recorded: 0, endpoints: 0, findings: 0 },
        folders: [],
        endpoints: [],
      }),
    }
    const { unmount } = render(
      <OriginPathsTab assetId="a1" assetName="https://shop.example.com" canCrawl={false} />
    )
    expect(screen.getByText('This site has not been crawled yet')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Crawl this site' })).toBeNull()
    unmount()
    render(<OriginPathsTab assetId="a1" assetName="https://shop.example.com" canCrawl />)
    await userEvent.click(screen.getByRole('button', { name: 'Crawl this site' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Crawl this site')
  })
})
