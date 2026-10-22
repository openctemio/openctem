import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { DashboardView } from '../components/dashboard-view'
import type { DashboardData } from '../api/widget-data'

const stat = (id: string, metric: string) => ({
  widget_type: 'metric',
  x: 0,
  y: 0,
  w: 6,
  h: 1,
  config: {
    v: 2,
    id,
    data: { kind: 'metric', metric, filter: {}, time: {} },
    viz: { type: 'stat', options: {} },
  },
})

describe('DashboardView', () => {
  it('one malformed result does not blank the other widgets', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const data = {
      dashboard_id: 'd',
      scope: 'personal',
      restricted: true,
      facts_built_at: 'x',
      computed_at: new Date().toISOString(),
      stale: false,
      widgets: [
        // A scalar whose value is an object: the stat throws while rendering.
        {
          id: 'w_bad',
          index: 0,
          widget_type: 'metric',
          state: 'ready',
          shape: 'scalar',
          scalar: { value: { boom: true } },
        },
        {
          id: 'w_ok',
          index: 1,
          widget_type: 'metric',
          state: 'ready',
          shape: 'scalar',
          metric: 'intel.kev_open',
          scalar: { value: 7 },
        },
      ],
    } as unknown as DashboardData
    render(
      <DashboardView
        dashboard={{
          layout: [stat('w_bad', 'findings.open'), stat('w_ok', 'intel.kev_open')],
          columns: 2,
        }}
        data={data}
        loading={false}
      />
    )
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(screen.getByText('KEV on your assets')).toBeInTheDocument()
    spy.mockRestore()
  })

  it('a failed request shows every widget as an error with its own title', () => {
    render(
      <DashboardView
        dashboard={{ layout: [stat('w_ok', 'intel.kev_open')], columns: 2 }}
        data={undefined}
        loading={false}
        failed
        onRetry={() => {}}
      />
    )
    expect(screen.getByText('KEV on your assets')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument()
  })

  it('an empty layout says how to add widgets', () => {
    render(
      <DashboardView dashboard={{ layout: [], columns: 2 }} data={undefined} loading={false} />
    )
    expect(screen.getByText(/no widgets yet/)).toBeInTheDocument()
  })
})
