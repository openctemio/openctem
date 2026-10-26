/**
 * /attack-paths: the flow canvas, the list view (default on a phone), the
 * hover and keyboard model, choke points whose counts equal the lists they
 * open, the score breakdown, steps outside the viewer's access, the states
 * (loading, error, no relationships, no target, no path) and axe.
 */
import axe from 'axe-core'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { mockupDetail, node } from '@/features/attack-surface/lib/__tests__/attack-path-fixture'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

let search = new URLSearchParams()
const replace = vi.fn()
const push = vi.fn()
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace, refresh: vi.fn() }),
  usePathname: () => '/attack-paths',
  useSearchParams: () => search,
}))

let mobile = false
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => mobile }))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({ useModuleEnabled: () => true }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
}))
vi.mock('@/features/remediation-hub/components/add-findings-to-task-dialog', () => ({
  AddFindingsToTaskDialog: ({ findings }: { findings: { id: string; title: string }[] }) => (
    <div data-testid="task-dialog">{findings.map((f) => f.id).join(',')}</div>
  ),
}))

const chains = vi.fn()
const detail = vi.fn()
vi.mock('@/features/attack-surface', async (orig) => ({
  ...(await orig<typeof import('@/features/attack-surface')>()),
  useExposureChains: () => chains(),
}))
vi.mock('@/features/attack-surface/hooks/use-attack-path-detail', async (orig) => ({
  ...(await orig<typeof import('@/features/attack-surface/hooks/use-attack-path-detail')>()),
  useAttackPathDetail: (id: string | null) => detail(id),
}))

import AttackPathsPage from '../attack-paths/page'

const chainsOk = {
  chains: {
    summary: { entryPoints: 1, targetsAtRisk: 1, totalChains: 1, hasRelationshipData: true },
    chains: [
      {
        entryPointId: 'asset-n1',
        entryPointName: 'vpn-gw-hq',
        targetId: 'asset-n0',
        targetName: 'billing-db',
        targetCriticality: 'critical',
        isCrownJewel: true,
        hops: [],
        length: 2,
        kevCount: 1,
        criticalCount: 1,
        score: 30,
      },
    ],
  },
  error: undefined,
  isLoading: false,
  mutate: vi.fn(),
}

// React Flow keeps nodes unmeasured (visibility hidden) in jsdom, so the
// accessible names are checked in the browser (e2e); here a node is found by its text.
const nodeBtn = (name: RegExp) => {
  const nodes = screen.getAllByTestId('flow-node')
  const el = nodes.find((n) => name.test(n.textContent ?? ''))
  if (!el) throw new Error(`no flow node matches ${String(name)}`)
  return el
}

const ok = (d = mockupDetail()) => ({
  detail: d,
  error: undefined,
  isLoading: false,
  mutate: vi.fn(),
})

async function violations(el: Element) {
  const res = await axe.run(el, {
    rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
  })
  return res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
}

beforeEach(() => {
  search = new URLSearchParams()
  mobile = false
  chains.mockReset().mockReturnValue(chainsOk)
  detail.mockReset().mockReturnValue(ok())
  replace.mockReset()
  push.mockReset()
})

describe('/attack-paths view', () => {
  it('asks for the first target and titles the page with it', () => {
    render(<AttackPathsPage />)
    expect(detail).toHaveBeenCalledWith('asset-n0')
    expect(
      screen.getByRole('heading', { level: 1, name: 'Path to billing-db' })
    ).toBeInTheDocument()
    expect(screen.getByText('2 hops')).toBeInTheDocument()
    expect(screen.getByText('Likelihood 0.22')).toBeInTheDocument()
  })

  it('draws the shortest path on the canvas, every path in All mode', () => {
    const { unmount } = render(<AttackPathsPage />)
    const canvas = screen.getByTestId('attack-path-canvas')
    expect(within(canvas).getAllByTestId('flow-node')).toHaveLength(3)
    expect(within(canvas).getByTestId('flow-internet')).toBeInTheDocument()
    unmount()
    search = new URLSearchParams('paths=all')
    render(<AttackPathsPage />)
    expect(
      within(screen.getByTestId('attack-path-canvas')).getAllByTestId('flow-node')
    ).toHaveLength(4)
  })

  it('switches the path mode through the URL', async () => {
    render(<AttackPathsPage />)
    await userEvent.click(screen.getByRole('button', { name: /Paths: Shortest/ }))
    await userEvent.click(await screen.findByRole('menuitemradio', { name: /All/ }))
    expect(replace).toHaveBeenCalledWith(expect.stringContaining('paths=all'), { scroll: false })
  })

  it('lights the routes through a hovered node and dims the rest', () => {
    search = new URLSearchParams('paths=all')
    render(<AttackPathsPage />)
    const ci = nodeBtn(/Hop[\s\S]*ci-runner-3/)
    fireEvent.mouseEnter(ci)
    expect(ci).toHaveAttribute('data-state', 'lit')
    expect(nodeBtn(/Hop[\s\S]*jump-host-02/)).toHaveAttribute('data-state', 'dim')
    expect(nodeBtn(/Entry point[\s\S]*vpn-gw-hq/)).toHaveAttribute('data-state', 'lit')
    fireEvent.mouseLeave(ci)
    expect(nodeBtn(/Hop[\s\S]*jump-host-02/)).toHaveAttribute('data-state', 'normal')
  })

  it('moves the focus along the edges with the arrow keys, one tab stop', () => {
    search = new URLSearchParams('paths=all')
    render(<AttackPathsPage />)
    const nodes = within(screen.getByTestId('attack-path-canvas')).getAllByTestId('flow-node')
    expect(nodes.filter((n) => n.tabIndex === 0)).toHaveLength(1)
    const entry = nodeBtn(/Entry point[\s\S]*vpn-gw-hq/)
    act(() => entry.focus())
    fireEvent.keyDown(entry, { key: 'ArrowRight' })
    expect(document.activeElement).toBe(nodeBtn(/Hop[\s\S]*jump-host-02/))
    fireEvent.keyDown(document.activeElement!, { key: 'ArrowDown' })
    expect(document.activeElement).toBe(nodeBtn(/Hop[\s\S]*ci-runner-3/))
    fireEvent.keyDown(document.activeElement!, { key: 'ArrowRight' })
    expect(document.activeElement).toBe(nodeBtn(/Crown jewel[\s\S]*billing-db/))
    // Enter opens the findings of the step; Escape clears the highlight.
    fireEvent.keyDown(document.activeElement!, { key: 'Enter' })
    expect(push).toHaveBeenCalledWith('/findings?asset_id=asset-n0&informational=true')
    fireEvent.keyDown(document.activeElement!, { key: 'Escape' })
    expect(nodeBtn(/Hop[\s\S]*jump-host-02/)).toHaveAttribute('data-state', 'normal')
  })

  it('cycles the selected path with the square brackets and the score card', () => {
    search = new URLSearchParams('paths=all')
    render(<AttackPathsPage />)
    expect(screen.getByText('Path 1 of 2')).toBeInTheDocument()
    fireEvent.keyDown(nodeBtn(/Entry point[\s\S]*vpn-gw-hq/), { key: ']' })
    expect(screen.getByText('Path 2 of 2')).toBeInTheDocument()
    expect(screen.getByTestId('path-likelihood')).toHaveTextContent('0.11')
    fireEvent.click(screen.getByRole('button', { name: 'Next path' }))
    expect(screen.getByText('Path 1 of 2')).toBeInTheDocument()
  })

  it('ranks choke points, and each findings count equals the list its link opens', () => {
    render(<AttackPathsPage />)
    const list = screen.getByTestId('choke-points')
    const rows = within(list).getAllByRole('listitem')
    expect(rows[0]).toHaveTextContent('Fix CVE-2026-30112 on vpn-gw-hq')
    expect(rows[0]).toHaveTextContent('Fix this to cut 2 of 2 paths')
    expect(rows[1]).toHaveTextContent('Cuts 1 of 2 paths')
    const link = within(rows[0]).getByTestId('node-findings-link')
    expect(link).toHaveTextContent('View 3 findings')
    expect(link).toHaveAttribute('href', '/findings?asset_id=asset-n1&informational=true')
    expect(link.getAttribute('data-count')).toBe('3')
  })

  it('shows the score of the selected path as a breakdown with finding links', () => {
    render(<AttackPathsPage />)
    const card = screen.getByTestId('path-score')
    expect(within(card).getByRole('link', { name: 'CVE-2026-30112' })).toHaveAttribute(
      'href',
      '/findings/f-vpn'
    )
    expect(card).toHaveTextContent('0.90')
    expect(card).toHaveTextContent('× 0.60')
    expect(card).toHaveTextContent('× 0.40')
    expect(within(card).getByTestId('path-likelihood')).toHaveTextContent('0.22')
  })

  it('creates a task for the first choke point', () => {
    render(<AttackPathsPage />)
    fireEvent.click(screen.getByTestId('choke-task'))
    expect(screen.getByTestId('task-dialog')).toHaveTextContent('f-vpn')
  })

  it('opens the list view from the switcher and by default on a phone', () => {
    search = new URLSearchParams('view=list')
    const { unmount } = render(<AttackPathsPage />)
    expect(screen.getByTestId('attack-path-list')).toBeInTheDocument()
    expect(screen.queryByTestId('attack-path-canvas')).not.toBeInTheDocument()
    unmount()
    search = new URLSearchParams()
    mobile = true
    render(<AttackPathsPage />)
    const list = screen.getByTestId('attack-path-list')
    expect(screen.queryByTestId('attack-path-canvas')).not.toBeInTheDocument()
    expect(within(list).getByText('Shortest path')).toBeInTheDocument()
    expect(within(list).getByText('From the internet through CVE-2026-30112')).toBeInTheDocument()
  })

  it('shows a step outside the access as a placeholder and withholds the likelihood', () => {
    const d = mockupDetail()
    d.nodes[2] = {
      ...node('n2', 'hop'),
      hidden: true,
      name: '',
      assetId: '',
      weight: null,
      basis: null,
      finding: null,
      openFindings: 0,
    }
    d.paths[0] = { ...d.paths[0], likelihood: null }
    d.chokePoints = d.chokePoints.filter((c) => c.node !== 'n2')
    detail.mockReturnValue(ok(d))
    render(<AttackPathsPage />)
    expect(nodeBtn(/Hop[\s\S]*Outside your access/)).toBeInTheDocument()
    expect(screen.getByTestId('path-likelihood')).toHaveTextContent('Withheld')
    expect(screen.queryByText(/^Likelihood /)).not.toBeInTheDocument()
  })

  it('has no axe violations on the canvas or the list view', async () => {
    search = new URLSearchParams('paths=all')
    const { container, unmount } = render(<AttackPathsPage />)
    expect(await violations(container)).toEqual([])
    unmount()
    search = new URLSearchParams('view=list')
    const list = render(<AttackPathsPage />)
    expect(await violations(list.container)).toEqual([])
  }, 30000)
})

describe('/attack-paths states', () => {
  it('shows a skeleton while loading', () => {
    detail.mockReturnValue({
      detail: undefined,
      error: undefined,
      isLoading: true,
      mutate: vi.fn(),
    })
    render(<AttackPathsPage />)
    expect(screen.getByTestId('attack-path-loading')).toBeInTheDocument()
  })

  it('shows an error state, not an empty state, when the detail read fails', () => {
    detail.mockReturnValue({
      detail: undefined,
      error: new Error('boom'),
      isLoading: false,
      mutate: vi.fn(),
    })
    render(<AttackPathsPage />)
    expect(screen.getByText(/Failed to load attack paths/i)).toBeInTheDocument()
  })

  it('shows an error state when the targets fail to load', () => {
    chains.mockReturnValue({
      chains: undefined,
      error: new Error('boom'),
      isLoading: false,
      mutate: vi.fn(),
    })
    detail.mockReturnValue({
      detail: undefined,
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    })
    render(<AttackPathsPage />)
    expect(screen.getByText(/Failed to load attack paths/i)).toBeInTheDocument()
    expect(detail).toHaveBeenCalledWith(null)
  })

  it('says when there are no relationships yet', () => {
    chains.mockReturnValue({
      ...chainsOk,
      chains: { summary: { ...chainsOk.chains.summary, hasRelationshipData: false }, chains: [] },
    })
    detail.mockReturnValue({
      detail: undefined,
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    })
    render(<AttackPathsPage />)
    expect(screen.getByText('No relationship data yet')).toBeInTheDocument()
  })

  it('says when no path reaches a dangerous asset', () => {
    chains.mockReturnValue({ ...chainsOk, chains: { ...chainsOk.chains, chains: [] } })
    detail.mockReturnValue({
      detail: undefined,
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    })
    render(<AttackPathsPage />)
    expect(screen.getByText('No path reaches a dangerous asset')).toBeInTheDocument()
  })

  it('says when no path reaches the chosen asset, honouring a target from the URL', () => {
    search = new URLSearchParams('target=asset-lone')
    detail.mockReturnValue(
      ok({
        ...mockupDetail(),
        nodes: [node('n0', 'target', { name: 'lone-box', isCrownJewel: false })],
        edges: [],
        paths: [],
        chokePoints: [],
        totalPaths: 0,
      })
    )
    render(<AttackPathsPage />)
    expect(detail).toHaveBeenCalledWith('asset-lone')
    expect(screen.getByText('No path from the internet reaches lone-box')).toBeInTheDocument()
  })

  it('says how many paths are shown when there are more', () => {
    detail.mockReturnValue(ok({ ...mockupDetail(), totalPaths: 30 }))
    render(<AttackPathsPage />)
    expect(screen.getByTestId('paths-capped')).toHaveTextContent('Showing 2 of 30 paths')
  })
})
