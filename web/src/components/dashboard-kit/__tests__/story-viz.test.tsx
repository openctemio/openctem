import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { I18nProvider } from '@/context/i18n-provider'
import { BriefViz, KpiStripViz, LeversViz } from '../story-viz'
import type { BriefResult, KpisResult, LeversResult } from '../types'

const levers: LeversResult = {
  shape: 'levers',
  levers: [
    {
      kind: 'one_fix',
      count: 27,
      assets: 14,
      title: 'Upgrade openssl to 3.0.15',
      effect: { metric: 'exposure.priority_open', before: 31, after: 19, unit: 'count' },
      href: '/remediation/suggestions',
    },
    {
      kind: 'sla_breached',
      count: 10,
      effect: { metric: 'sla.within', before: 60, after: 66.7, unit: 'percent' },
      href: '/findings?priority_class=P0,P1&sla_status=overdue,exceeded&state=open',
    },
    {
      kind: 'blind_spot',
      count: 1,
      effect: { metric: 'coverage.discovery', before: 75, after: 100, unit: 'percent' },
      href: null,
    },
  ],
}

describe('LeversViz', () => {
  it('words each lever with its exact effect and opens its list', () => {
    render(<LeversViz result={levers} />)
    const items = screen.getAllByRole('listitem')
    expect(items).toHaveLength(3)
    expect(items[0]).toHaveTextContent('31 → 19')
    expect(items[0]).toHaveTextContent(
      'Upgrade openssl to 3.0.15 closes 27 findings on 14 assets; P0–P1 open goes from 31 to 19.'
    )
    expect(within(items[0]).getByRole('link')).toHaveAttribute('href', '/remediation/suggestions')
    expect(items[1]).toHaveTextContent('10 P0–P1 findings are past the SLA')
    // Singular, and no link without a list.
    expect(items[2]).toHaveTextContent('1 tracked asset has no successful scan')
    expect(within(items[2]).queryByRole('link')).toBeNull()
  })

  it('never uses an accent stripe or a middle-dot separator', () => {
    const { container } = render(<LeversViz result={levers} />)
    expect(container.innerHTML).not.toMatch(/border-l-|border-s-\d|border-t-\d/)
    expect(container.textContent).not.toContain(' · ')
  })

  it('says so when nothing stands out', () => {
    render(<LeversViz result={{ shape: 'levers', levers: [] }} />)
    expect(screen.getByText(/Nothing stands out/)).toBeInTheDocument()
  })

  it('renders in Vietnamese', () => {
    render(
      <I18nProvider locale="vi">
        <LeversViz result={levers} />
      </I18nProvider>
    )
    expect(screen.getByText('Một bản sửa')).toBeInTheDocument()
    expect(screen.getByText(/đóng 27 phát hiện trên 14 tài sản/)).toBeInTheDocument()
  })
})

const brief: BriefResult = {
  shape: 'brief',
  since: '2026-10-23T00:00:00Z',
  items: [
    {
      kind: 'change',
      variant: 'down',
      chips: [
        { key: 'opened', value: 8, href: null },
        { key: 'fixed', value: 13, href: null },
      ],
    },
    {
      kind: 'sla_due',
      chips: [
        { key: 'due_soon', value: 4, href: '/findings?sla_status=warning&state=open' },
        { key: 'past_sla', value: 10, href: '/findings?sla_status=overdue,exceeded&state=open' },
      ],
    },
  ],
}

describe('BriefViz', () => {
  it('builds each sentence from its figures and links only exact lists', () => {
    render(<BriefViz result={brief} />)
    const items = screen.getAllByRole('listitem')
    expect(items[0]).toHaveTextContent('Open exposure fell this week: 13 fixed against 8 new.')
    expect(within(items[0]).queryByRole('link')).toBeNull()
    expect(items[1]).toHaveTextContent('4 P0–P2 findings reach the SLA soon, and 10 are past it.')
    const links = within(items[1]).getAllByRole('link')
    expect(links.map((a) => a.getAttribute('href'))).toEqual([
      '/findings?sla_status=warning&state=open',
      '/findings?sla_status=overdue,exceeded&state=open',
    ])
    expect(screen.getByText(/no AI involved/)).toBeInTheDocument()
  })

  it('shows the quiet sentence when every sentence was removed', () => {
    render(<BriefViz result={{ shape: 'brief', since: '2026-10-23T00:00:00Z', items: [] }} />)
    expect(screen.getByText('Nothing changed this week that needs attention.')).toBeInTheDocument()
  })
})

const kpis: KpisResult = {
  shape: 'kpis',
  tiles: [
    {
      key: 'priority_open',
      metric: 'exposure.priority_open',
      measured: true,
      value: 31,
      previous: 43,
      unit: 'count',
      polarity: 'down_good',
      href: '/findings?priority_class=P0,P1&state=open',
    },
    {
      key: 'kev_open',
      metric: 'intel.kev_open',
      measured: true,
      value: 9,
      previous: 7,
      unit: 'count',
      polarity: 'down_good',
      href: '/findings?is_in_kev=true&state=open',
    },
    {
      key: 'sla_within',
      metric: 'sla.within',
      measured: true,
      value: 78,
      previous: null,
      unit: 'percent',
      polarity: 'up_good',
      href: '/findings?sla_status=overdue,exceeded&state=open',
    },
    {
      key: 'time_to_fix',
      metric: 'fix.time_to_fix',
      measured: false,
      reason_key: 'dashboards.reason.too_few_fixed',
      value: null,
      previous: null,
      unit: 'hours',
      polarity: 'down_good',
      href: null,
    },
    {
      key: 'coverage',
      metric: 'coverage.discovery',
      measured: true,
      value: 91,
      previous: null,
      unit: 'percent',
      polarity: 'up_good',
      href: '/assets?coverage=uncovered&program_assets=exclude',
    },
  ],
}

describe('KpiStripViz', () => {
  it('draws five figures in one strip, each opening its list', () => {
    const { container } = render(<KpiStripViz result={kpis} />)
    expect(container.querySelectorAll('[data-slot="metric-strip"]')).toHaveLength(1)
    const tiles = container.querySelectorAll('[data-slot="metric-tile"]')
    expect(tiles).toHaveLength(5)
    expect(tiles[0]).toHaveTextContent('P0–P1 open')
    expect(tiles[0]).toHaveAttribute('href', '/findings?priority_class=P0,P1&state=open')
    expect(tiles[2]).toHaveTextContent('78')
    // Not measured: no number, no link.
    expect(tiles[3]).toHaveTextContent('Not measured')
    expect(tiles[3].tagName).not.toBe('A')
    expect(tiles[3]).toHaveAttribute('data-state', 'not-measured')
    expect(tiles[0]).not.toHaveAttribute('data-state')
  })
})
