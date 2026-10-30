import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'
import { ItemsTable } from '../items-table'
import type { ItemsResult } from '../types'

const soon = new Date(Date.now() + 3 * 86_400_000).toISOString()
const result: ItemsResult = {
  shape: 'items',
  total: 791,
  rows: [
    {
      id: 'f1',
      title: 'Exposed admin panel',
      priority: 'P0',
      severity: 'critical',
      asset: 'portal.example.com',
      due_at: soon,
      kev: true,
      href: '/findings/f1',
    },
    {
      id: 'f2',
      title: '',
      priority: 'P1',
      severity: 'low',
      asset: null,
      due_at: null,
      kev: false,
      href: '/findings/f2',
    },
  ],
}

describe('ItemsTable', () => {
  it('renders a row per finding with its link, asset line, KEV chip and priority', () => {
    render(<ItemsTable result={result} viewAllHref="/findings?priority_class=P0,P1,P2" />)
    const rows = screen.getAllByRole('row').slice(1)
    expect(rows).toHaveLength(2)
    const first = within(rows[0])
    expect(first.getByRole('link', { name: 'Exposed admin panel' })).toHaveAttribute(
      'href',
      '/findings/f1'
    )
    expect(first.getByText('portal.example.com')).toBeInTheDocument()
    expect(first.getByText('KEV')).toBeInTheDocument()
    expect(first.getByRole('img', { name: /P0/ })).toBeInTheDocument()
    expect(first.getByText(/due in 3 days/)).toBeInTheDocument()
    // An untitled finding gets a named placeholder, and no deadline says so.
    expect(within(rows[1]).getByRole('link', { name: 'Untitled finding' })).toBeInTheDocument()
    expect(within(rows[1]).getByText('No due date')).toBeInTheDocument()
  })

  it('the footer says how much of the list it shows and opens the same list', () => {
    render(<ItemsTable result={result} viewAllHref="/findings?priority_class=P0,P1,P2" />)
    expect(screen.getByTestId('items-table-footer')).toHaveTextContent('Top 2 of 791')
    expect(screen.getByRole('link', { name: 'Open in Findings' })).toHaveAttribute(
      'href',
      '/findings?priority_class=P0,P1,P2'
    )
  })

  it('without a total it never claims one, and an off-site link is dropped', () => {
    render(<ItemsTable result={{ ...result, total: null }} viewAllHref="//evil.example.com" />)
    expect(screen.getByTestId('items-table-footer')).toHaveTextContent('Top 2')
    expect(screen.getByTestId('items-table-footer')).not.toHaveTextContent('of')
    expect(screen.queryByRole('link', { name: 'Open in Findings' })).toBeNull()
  })

  it('shows the list filters as read-only chips', () => {
    render(<ItemsTable result={result} filters={['Open', 'Priority P0–P2']} />)
    const chips = screen.getAllByTestId('items-table-filter').map((c) => c.textContent)
    expect(chips).toEqual(['Open', 'Priority P0–P2'])
  })

  it('hides Severity and SLA at phone width and scrolls sideways', () => {
    const { container } = render(<ItemsTable result={result} />)
    for (const col of ['severity', 'sla']) {
      const th = container.querySelector(`th[data-col="${col}"]`)!
      expect(th.className).toContain('hidden')
      expect(th.className).toContain('sm:table-cell')
    }
    expect(container.querySelector('.overflow-x-auto table')).not.toBeNull()
    // Priority and Finding stay at every width.
    expect(screen.getByRole('columnheader', { name: 'Priority' }).className).not.toContain('hidden')
    expect(screen.getByRole('columnheader', { name: 'Finding' }).className).not.toContain('hidden')
  })

  it('renders in Vietnamese', () => {
    render(
      <I18nProvider locale="vi">
        <ItemsTable result={result} viewAllHref="/findings" />
      </I18nProvider>
    )
    expect(screen.getByTestId('items-table-footer')).toHaveTextContent('Top 2 trong 791')
    expect(screen.getByRole('link', { name: 'Mở trong Phát hiện' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Ưu tiên' })).toBeInTheDocument()
  })
})
