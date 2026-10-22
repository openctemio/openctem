/**
 * Accessibility of the dashboard surfaces, checked with axe-core: a dashboard
 * with every result shape, the editor and the gallery. Colour contrast is
 * checked in the browser suite (jsdom does not compute colours).
 */
import axe from 'axe-core'
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { DashboardData } from '../api/widget-data'
import type { WidgetCatalog } from '../api/widget-spec'
import { DashboardView } from '../components/dashboard-view'
import { DashboardFreshness } from '../components/dashboard-freshness'
import { DashboardEditor } from '../editor/dashboard-editor'
import { DASHBOARD_TEMPLATES, templateLayout } from '../templates'

vi.mock('../api/use-dashboards-api', () => ({
  updateDashboard: vi.fn(),
  updateOrgDashboard: vi.fn(),
}))
vi.mock('../api/widget-data', () => ({
  previewWidget: vi.fn(() => new Promise(() => {})),
}))
vi.mock('../api/widget-spec', async (orig) => ({
  ...(await orig<typeof import('../api/widget-spec')>()),
  useWidgetCatalog: () => ({
    data: {
      spec_version: 2,
      metrics: [
        {
          id: 'findings.open',
          group: 'exposure',
          filters: ['severity'],
          group_bys: ['severity'],
          max_group_by: 1,
          default_group_by: [],
          default_filter: {},
          polarity: 'lower_better',
          timed: false,
          flow: false,
          shapes: {
            '0': { shape: 'scalar', vizzes: ['stat'] },
            '1': { shape: 'category', vizzes: ['bar'] },
          },
        },
      ],
      dimensions: { severity: ['critical', 'high'] },
      time_ranges: ['inherit'],
      time_buckets: ['auto'],
      comparisons: ['none'],
      target_ops: ['<='],
    } as WidgetCatalog,
    isLoading: false,
  }),
}))

async function violations(node: Element) {
  const res = await axe.run(node, {
    rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
  })
  return res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
}

const series = (keys: string[]) =>
  keys.map((key) => ({
    key,
    points: [
      { t: '2026-10-01', v: 3 },
      { t: '2026-10-08', v: 5 },
    ],
  }))

/** The Overview template with a result of each shape. */
function overview(): { layout: ReturnType<typeof templateLayout>; data: DashboardData } {
  const tpl = DASHBOARD_TEMPLATES.find((t) => t.key === 'overview')!
  const layout = templateLayout(tpl)
  const widgets = layout.map((w, i) => {
    const metric = (w.config as { data: { metric: string } }).data.metric
    const base = {
      id: (w.config as { id: string }).id,
      index: i,
      widget_type: 'metric',
      state: 'ready' as const,
      metric,
    }
    switch (metric) {
      case 'sla.within':
        return { ...base, shape: 'ratio' as const, ratio: { num: 86, den: 100, value_pct: 86 } }
      case 'fix.time_to_fix':
        return {
          ...base,
          shape: 'duration' as const,
          duration: { median_hours: 130, p90_hours: 400, n: 40, bucketed: true },
        }
      case 'exposure.open_by_priority':
        return {
          ...base,
          shape: 'time_series' as const,
          series: { bucket: 'week', series: series(['P0', 'P1']) },
        }
      case 'flow.new_vs_fixed':
        return {
          ...base,
          shape: 'time_series' as const,
          series: { bucket: 'week', series: series(['opened', 'fixed']) },
        }
      case 'fix.next':
      case 'sla.at_risk':
        return {
          ...base,
          shape: 'items' as const,
          items: {
            rows: [
              {
                id: 'f1',
                title: 'RCE in edge gateway',
                severity: 'critical',
                priority_class: 'P0',
                kev: true,
              },
            ],
          },
        }
      case 'findings.age_bands':
        return {
          ...base,
          shape: 'matrix' as const,
          matrix: { rows: ['high'], cols: ['0-30', '90+'], cells: [[2, 1]] },
        }
      default:
        return {
          ...base,
          shape: 'scalar' as const,
          scalar: { value: 31, previous: 43, delta: -12 },
        }
    }
  })
  return {
    layout,
    data: {
      dashboard_id: 'd',
      scope: 'personal',
      restricted: true,
      facts_built_at: '2026-10-21T00:00:00Z',
      computed_at: new Date().toISOString(),
      next_refresh_at: new Date(Date.now() + 3_600_000).toISOString(),
      stale: false,
      widgets,
    },
  }
}

describe('dashboard accessibility', () => {
  it('a dashboard with every result shape has no axe violations', async () => {
    const { layout, data } = overview()
    const { container } = render(
      <main>
        <DashboardFreshness
          kind="personal"
          data={data}
          canSchedule
          onRefresh={async () => {}}
          onSchedule={async () => {}}
        />
        <DashboardView dashboard={{ layout, columns: 4 }} data={data} loading={false} />
      </main>
    )
    expect(await violations(container)).toEqual([])
  })

  it('the editor and the gallery have no axe violations', async () => {
    const { layout, data } = overview()
    render(
      <main>
        <DashboardEditor
          dashboard={{ id: 'd', name: 'Overview', is_default: true, columns: 4, layout }}
          kind="personal"
          data={data}
          onExit={() => {}}
        />
      </main>
    )
    expect(await violations(document.body)).toEqual([])
    await userEvent.click(screen.getByRole('button', { name: 'Add widget' }))
    await screen.findByRole('dialog', { name: 'Add a widget' })
    expect(await violations(document.body)).toEqual([])
  }, 30_000)
})
