import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import type { DashboardData, WidgetValue } from '../api/widget-data'

vi.mock('@/context/permission-provider', () => ({
  usePermissionsSafe: () => ({ hasPermission: () => true }),
}))
vi.mock('@/components/ui/markdown-editor', () => ({ MarkdownPreview: () => null }))
vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))

import { widgetModel } from '../api/widget-adapter'
import { DashboardView } from '../components/dashboard-view'
import { WidgetView } from '../components/widget-view'

const cfg = (metric: string, viz: string) => ({
  v: 2,
  id: 'w',
  data: { kind: 'metric' as const, metric, filter: {}, time: {} },
  viz: { type: viz, options: {} },
})
const widget = (metric: string, viz: string, h = 1) => ({
  widget_type: 'metric',
  x: 0,
  y: 0,
  w: 6,
  h,
  config: cfg(metric, viz),
})
const base = { id: 'w', index: 0, widget_type: 'metric' } as const

describe('the one compact empty state', () => {
  it('a scope with no finding is "No data yet" with the next step, never a figure', () => {
    const v: WidgetValue = {
      ...base,
      metric: 'exposure.priority_open',
      state: 'not_measured',
      reason: 'no_findings',
    }
    const m = widgetModel(v, undefined, false)
    expect(m.state).toBe('no_data_yet')
    expect(m.reasonKey).toBe('dashboards.reason.no_findings')
    render(<WidgetView widget={widget('exposure.priority_open', 'stat')} value={v} />)
    expect(screen.getByText('No data yet')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Import results' })).toBeInTheDocument()
    // No target chip, no number.
    expect(screen.queryByText(/target/i)).toBeNull()
  })

  it('a series whose every bucket is zero draws no axes', () => {
    const v: WidgetValue = {
      ...base,
      metric: 'flow.new_vs_fixed',
      state: 'ready',
      shape: 'time_series',
      series: {
        bucket: 'day',
        series: [
          { key: 'opened', points: [{ t: '2026-10-01', v: 0 }] },
          { key: 'fixed', points: [{ t: '2026-10-01', v: 0 }] },
        ],
      },
    }
    expect(widgetModel(v, undefined, false).state).toBe('no_data_yet')
  })

  it('a reason that is not "nothing yet" keeps the not-measured dash', () => {
    const v: WidgetValue = {
      ...base,
      metric: 'fix.time_to_fix',
      state: 'not_measured',
      reason: 'too_few_fixed',
    }
    expect(widgetModel(v, undefined, false).state).toBe('not_measured')
  })

  it('an empty widget takes one row of the grid, a measured one keeps its height', () => {
    const data = {
      dashboard_id: 'd',
      scope: 'organization',
      restricted: false,
      facts_built_at: 'x',
      computed_at: new Date().toISOString(),
      stale: false,
      widgets: [
        { ...base, index: 0, metric: 'fix.next', state: 'not_measured', reason: 'no_findings' },
        {
          ...base,
          index: 1,
          metric: 'intel.kev_open',
          state: 'ready',
          shape: 'scalar',
          scalar: { value: 2 },
        },
      ],
    } as unknown as DashboardData
    const { container } = render(
      <DashboardView
        dashboard={{
          layout: [widget('fix.next', 'table', 4), widget('intel.kev_open', 'stat', 2)],
          columns: 2,
        }}
        data={data}
        loading={false}
      />
    )
    const cells = container.querySelectorAll<HTMLElement>('[data-widget-index]')
    expect(cells[0].style.getPropertyValue('--row-span')).toBe('span 1 / span 1')
    expect(cells[0].dataset.compact).toBe('true')
    expect(cells[1].style.getPropertyValue('--row-span')).toBe('span 2 / span 2')
  })
})

describe('KEV shows its population', () => {
  it('"of N open" opens the open findings list', () => {
    const v: WidgetValue = {
      ...base,
      metric: 'intel.kev_open',
      state: 'ready',
      shape: 'scalar',
      scalar: { value: 0, of: 40, of_drill: '/findings?state=open' },
    }
    render(<WidgetView widget={widget('intel.kev_open', 'stat')} value={v} />)
    const link = screen.getByRole('link', { name: 'of 40 open' })
    expect(link.getAttribute('href')).toBe('/findings?state=open')
  })
})

describe('discovery coverage says why', () => {
  it('lists the uncovered assets by cause, each opening its list', () => {
    const v: WidgetValue = {
      ...base,
      metric: 'coverage.discovery',
      state: 'ready',
      shape: 'ratio',
      ratio: {
        num: 4,
        den: 10,
        value_pct: 40,
        causes: [
          {
            key: 'no_sensor',
            value: 5,
            drill: '/assets?coverage=uncovered&coverage_cause=no_sensor&program_assets=exclude',
          },
          { key: 'overdue', value: 1, drill: '/assets?coverage=uncovered&coverage_cause=overdue' },
        ],
      },
    }
    render(<WidgetView widget={widget('coverage.discovery', 'progress')} value={v} />)
    expect(screen.getByText('Why assets are not covered')).toBeInTheDocument()
    const link = screen.getByRole('link', { name: /No eligible sensor/ })
    expect(link.getAttribute('href')).toBe(
      '/assets?coverage=uncovered&coverage_cause=no_sensor&program_assets=exclude'
    )
  })
})
