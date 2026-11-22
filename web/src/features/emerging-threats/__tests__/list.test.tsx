import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import { EmergingThreatsList } from '../components/emerging-threats-list'
import { listUrl } from '../api'
import { detail, host, service, summary } from './fixtures'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
// The mocked member holds every permission; the API is the authority.
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))
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
    summary({
      id: 'a2',
      vuln_id: 'CVE-2026-2000',
      title: 'CVE-2026-2000 \u00b7 Gadget',
      product: 'Gadget',
      product_count: 1,
      level: 'digest',
      in_kev: false,
      kev_ransomware: false,
      epss: 0.006,
      confirmed_hosts: 0,
      likely_hosts: 0,
      possible_hosts: 4,
      internet_facing_hosts: 0,
      critical_hosts: 0,
      state: 'acknowledged',
    }),
  ],
  total: 2,
  page: 1,
  per_page: 25,
  total_pages: 1,
  summary: { open: 2, new: 1, immediate: 1, digest: 1, listed: 0, kev: 1, internet_facing: 1 },
}

const renderList = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <EmergingThreatsList />
    </SWRConfig>
  )

beforeEach(() => {
  // The list reads its filters from the address bar of its own page.
  window.history.replaceState(null, '', '/emerging-threats')
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
  it('opens with the filters of its URL (a dashboard level link)', async () => {
    window.history.replaceState(
      null,
      '',
      '/emerging-threats?level=immediate&state=open&tier=confirmed&kev=true'
    )
    renderList()
    await screen.findByText('CVE-2026-1000')
    expect(api.get).toHaveBeenCalledWith(
      '/api/v1/emerging-threats?level=immediate&state=open&tier=confirmed&kev=true&page=1&per_page=25'
    )
    expect(api.get).not.toHaveBeenCalledWith(
      '/api/v1/emerging-threats?state=open&page=1&per_page=25'
    )
    // Active filters show as removable chips under the toolbar.
    expect(screen.getByText('Priority is Act now')).toBeInTheDocument()
    expect(screen.getByText('Known exploited only')).toBeInTheDocument()
  })

  it('the threat column names the product once, never the id twice or a middot', async () => {
    renderList()
    const id = await screen.findByText('CVE-2026-2000')
    const cell = id.closest('td') as HTMLElement
    expect(within(cell).getByText('Gadget')).toBeInTheDocument()
    expect(cell.textContent).not.toContain('\u00b7')
    expect(cell.textContent?.match(/CVE-2026-2000/g)).toHaveLength(1)
    // The first row has two products: "+1".
    const first = (screen.getByText('CVE-2026-1000').closest('td') as HTMLElement).textContent
    expect(first).toContain('Widget')
    expect(first).toContain('+1')
  })

  it('shows priority words, not notification cadence', async () => {
    renderList()
    await screen.findByText('CVE-2026-1000')
    expect(screen.getAllByText('Act now').length).toBeGreaterThan(0)
    expect(screen.getAllByText('This week').length).toBeGreaterThan(0)
    expect(screen.queryByText('Immediate')).not.toBeInTheDocument()
    expect(screen.queryByText('Digest')).not.toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Priority' })).toBeInTheDocument()
  })

  it('exploit: KEV hides the EPSS figure; without KEV it reads "Exploit chance"', async () => {
    renderList()
    await screen.findByText('CVE-2026-1000')
    expect(screen.getAllByText('KEV').length).toBeGreaterThan(0)
    expect(screen.queryByText('Exploit chance 50.0%')).not.toBeInTheDocument()
    expect(screen.getByText('Exploit chance 0.6%')).toBeInTheDocument()
  })

  it('the affected column counts hosts in words, likely on its own, zeros left out', async () => {
    renderList()
    await screen.findByText('CVE-2026-1000')
    const cells = document.querySelectorAll('[data-slot="affected-cell"]')
    expect(cells).toHaveLength(2)
    // 3 confirmed, 1 likely, 2 possible, 1 internet-facing, 1 crown jewel.
    expect(cells[0].textContent).toBe('3 hosts confirmed+1 likely+2 possibly affected11')
    // The second row: 0 confirmed, 4 possible, nothing else.
    expect(cells[1].textContent).toBe('4 hosts possibly affected')
    const label = cells[1].getAttribute('aria-label') ?? ''
    expect(label).toContain('Affected hosts: 0 confirmed, 0 likely, 4 possibly affected')
    expect(label).not.toMatch(/assets/i)
  })

  it('the strip is five filter tiles: act now, untriaged, this week, known exploited, internet-facing', async () => {
    renderList()
    await screen.findByText('CVE-2026-1000')
    const tiles = document.querySelectorAll('[data-slot="metric-strip"] > *')
    expect(tiles).toHaveLength(5)
    const strip = document.querySelector('[data-slot="metric-strip"]') as HTMLElement
    await userEvent.click(within(strip).getByRole('button', { name: /Untriaged/ }))
    await waitFor(() => expect(window.location.search).toBe('?state=new'))
    await userEvent.click(within(strip).getByRole('button', { name: /Known exploited/ }))
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith(
        '/api/v1/emerging-threats?state=new&kev=true&page=1&per_page=25'
      )
    )
    await userEvent.click(within(strip).getByRole('button', { name: /Act now/ }))
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith(
        '/api/v1/emerging-threats?level=immediate&state=new&kev=true&page=1&per_page=25'
      )
    )
  })

  it('writes a filter to the URL and back to page 1', async () => {
    window.history.replaceState(null, '', '/emerging-threats?page=3&keep=1')
    renderList()
    await screen.findByText('CVE-2026-1000')
    const strip = document.querySelector('[data-slot="metric-strip"]') as HTMLElement
    await userEvent.click(within(strip).getByRole('button', { name: /This week/ }))
    await waitFor(() => expect(window.location.search).toBe('?keep=1&level=digest'))
    await userEvent.click(within(strip).getByRole('button', { name: /Internet-facing/ }))
    await waitFor(() =>
      expect(window.location.search).toBe('?keep=1&level=digest&exposure=internet')
    )
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

  it('has one toolbar: no second toolbar row for Display', async () => {
    renderList()
    await screen.findByText('CVE-2026-1000')
    expect(document.querySelectorAll('[data-slot="list-toolbar"]')).toHaveLength(1)
  })

  it('a row action acknowledges the alert', async () => {
    api.post.mockResolvedValue({})
    renderList()
    await screen.findByText('CVE-2026-1000')
    await userEvent.click(screen.getByRole('button', { name: 'Actions for CVE-2026-1000' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Acknowledge' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/emerging-threats/a1/state', {
        state: 'acknowledged',
      })
    )
  })

  it('clicking a row opens the drawer with the score breakdown and product versions', async () => {
    api.get.mockImplementation((url: string) =>
      Promise.resolve(
        url.startsWith('/api/v1/emerging-threats/a1')
          ? detail({
              confirmed_hosts: 2,
              likely_hosts: 1,
              possible_hosts: 1,
              asset_groups: [
                {
                  tier: 'confirmed',
                  hosts: [
                    // One host on two ports: one row, one host for its version.
                    host('192.0.2.20', [
                      service('http', { asset_id: 'as1', asset_name: 'http://192.0.2.20' }),
                      service('https', { asset_id: 'as4', asset_name: 'https://192.0.2.20' }),
                    ]),
                    host(
                      'web-02',
                      [
                        service('', {
                          asset_id: 'as2',
                          asset_name: 'web-02',
                          criticality: 'critical',
                        }),
                      ],
                      { asset_id: 'as2', criticality: 'critical' }
                    ),
                  ],
                },
                {
                  tier: 'likely',
                  hosts: [
                    host('192.0.2.30', [service('https', { asset_id: 'as5', tier: 'likely' })]),
                  ],
                },
                {
                  tier: 'possible',
                  hosts: [
                    host(
                      'web-03',
                      [service('', { asset_id: 'as3', version_seen: '', tier: 'possible' })],
                      { asset_id: 'as3' }
                    ),
                  ],
                },
              ],
            })
          : page
      )
    )
    renderList()
    await userEvent.click(
      await screen
        .findByText('Remote code execution in Widget')
        .catch(() => screen.getByText('Widget'))
    )
    const sheet = await screen.findByTestId('emerging-threat-sheet')
    expect(await within(sheet).findByText('Why it is ranked here')).toBeInTheDocument()
    expect(within(sheet).getByText('Exploitation')).toBeInTheDocument()
    const products = within(sheet).getByTestId('et-products')
    expect(products.textContent).toContain('1.2.3')
    // Three hosts run 1.2.3 (four services), one an unknown version.
    expect(products.textContent).toContain('Hosts: 3')
    expect(products.textContent).toContain('Version unknown')
    expect(products.textContent).not.toMatch(/Assets/)
    // The tile says confirmed hosts only; likely and possible beside it.
    expect(within(sheet).getByText('Hosts confirmed')).toBeInTheDocument()
    expect(within(sheet).getByText('+1 likely, +1 possibly affected')).toBeInTheDocument()
    // One row per host, crown jewels first; the two-port host is one row
    // that lists both services.
    const rows = within(within(sheet).getByTestId('et-top-hosts')).getAllByRole('listitem')
    const top = rows.filter(
      (li) => li.parentElement?.getAttribute('data-testid') === 'et-top-hosts'
    )
    expect(top).toHaveLength(4)
    expect(top[0].textContent).toContain('web-02')
    const twoPorts = top.find((li) => li.textContent?.includes('192.0.2.20')) as HTMLElement
    expect(within(twoPorts).getByRole('link', { name: 'http' })).toHaveAttribute(
      'href',
      '/assets/as1'
    )
    expect(within(twoPorts).getByRole('link', { name: 'https' })).toHaveAttribute(
      'href',
      '/assets/as4'
    )
    expect(within(sheet).getByText('Most important affected hosts')).toBeInTheDocument()
  })

  it('shows the API error', async () => {
    api.get.mockRejectedValue(new Error('boom'))
    renderList()
    expect(await screen.findByText('boom')).toBeInTheDocument()
  })
})
