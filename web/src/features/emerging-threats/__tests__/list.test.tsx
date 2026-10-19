import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import { EmergingThreatsList } from '../components/emerging-threats-list'
import { listUrl } from '../api'
import { summary } from './fixtures'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
  usePathname: () => '/emerging-threats',
  useSearchParams: () => new URLSearchParams(),
}))
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const page = {
  data: [
    summary(),
    summary({ id: 'a2', vuln_id: 'CVE-2026-2000', title: 'Other', level: 'digest' }),
  ],
  total: 2,
  page: 1,
  per_page: 25,
  total_pages: 1,
  summary: { open: 2, immediate: 1, digest: 1, listed: 0, kev: 1, internet_facing: 1 },
}

const renderList = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <EmergingThreatsList />
    </SWRConfig>
  )

beforeEach(() => {
  api.get.mockReset()
  api.get.mockResolvedValue(page)
})

describe('listUrl', () => {
  it('defaults to open alerts, page 1', () => {
    expect(listUrl({})).toBe('/api/v1/emerging-threats?state=open&page=1&per_page=25')
  })
  it('sends every filter', () => {
    const u = new URL(
      listUrl({
        level: 'immediate',
        state: 'all',
        tier: 'possible',
        internetOnly: true,
        search: ' CVE-2026 ',
        page: 3,
      }),
      'http://x'
    )
    expect(Object.fromEntries(u.searchParams)).toEqual({
      level: 'immediate',
      state: 'all',
      tier: 'possible',
      exposure: 'internet',
      search: 'CVE-2026',
      page: '3',
      per_page: '25',
    })
  })
})

describe('EmergingThreatsList', () => {
  it('renders rows with level, exploit status and counts', async () => {
    renderList()
    expect(await screen.findByText('CVE-2026-1000')).toBeInTheDocument()
    expect(screen.getByText('Remote code execution in Widget')).toBeInTheDocument()
    expect(screen.getByText('CVE-2026-2000')).toBeInTheDocument()
    expect(screen.getAllByText('KEV').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Ransomware').length).toBeGreaterThan(0)
    expect(screen.getAllByText('EPSS 50.0%').length).toBeGreaterThan(0)
    expect(
      screen.getAllByText(/3 confirmed · 2 possible · 1 internet-facing/).length
    ).toBeGreaterThan(0)
    expect(api.get).toHaveBeenCalledWith('/api/v1/emerging-threats?state=open&page=1&per_page=25')
  })

  it('searching sends the search query', async () => {
    renderList()
    await screen.findByText('CVE-2026-1000')
    await userEvent.type(screen.getByLabelText('Search'), 'CVE-2026-1000')
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith(
        '/api/v1/emerging-threats?state=open&search=CVE-2026-1000&page=1&per_page=25'
      )
    )
  })

  it('the internet-facing switch sends exposure=internet', async () => {
    renderList()
    await screen.findByText('CVE-2026-1000')
    await userEvent.click(screen.getByRole('switch', { name: 'Internet-facing only' }))
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith(
        '/api/v1/emerging-threats?state=open&exposure=internet&page=1&per_page=25'
      )
    )
  })

  it('the immediate card filters by level', async () => {
    renderList()
    await screen.findByText('CVE-2026-1000')
    await userEvent.click(screen.getByRole('button', { name: /Immediate/ }))
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith(
        '/api/v1/emerging-threats?level=immediate&state=open&page=1&per_page=25'
      )
    )
  })

  it('shows the API error', async () => {
    api.get.mockRejectedValue(new Error('boom'))
    renderList()
    expect(await screen.findByText('boom')).toBeInTheDocument()
  })
})
