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
      case 'exposure.flow': {
        const fig = (value: number, drill: string) => ({ value, drill })
        const src = (tool: string, health: 'ok' | 'stale' | 'failed') => ({
          origin: 'sensor' as const,
          tool,
          receipts: 3,
          received: 40,
          created: 10,
          still_detected: 25,
          reopened: 1,
          closed: 0,
          suppressed: 2,
          not_stored: 2,
          last_at: new Date().toISOString(),
          last_status: health === 'failed' ? 'failed' : 'completed',
          last_receipt_id: 'r1',
          health,
          drill: `/findings/imports?origin=sensor&tool=${tool}`,
        })
        const intake = {
          since: new Date(Date.now() - 30 * 86_400_000).toISOString(),
          sources: [src('nuclei', 'ok'), src('cloud', 'stale'), src('trivy', 'failed')],
          totals: { ...src('', 'ok'), received: 120, receipts: 9 },
          noise: { received: 120, new: 27, merged: 81, suppressed: 6, not_stored: 6 },
          failing: 1,
          stale: 1,
          drill: '/findings/imports',
          false_positive: fig(4, '/findings?status=false_positive'),
        }
        return {
          ...base,
          shape: 'flow' as const,
          flow: {
            since: intake.since,
            intake,
            actionable: fig(31, '/findings?state=open&priority_class=P0,P1,P2,P3'),
            classes: ['P0', 'P1', 'P2', 'P3'].map((k, j) => ({
              key: k,
              value: j + 1,
              drill: `/findings?priority_class=${k}`,
            })),
            open: fig(33, '/findings?state=open'),
            severity: [{ key: 'high', value: 33, drill: '/findings?severity=high' }],
            past_sla: fig(2, '/findings?sla_status=overdue'),
            in_progress: fig(3, '/findings?status=in_progress'),
            fixed: fig(5, '/findings?status=resolved'),
            accepted: fig(1, '/findings?status=accepted'),
            false_positive: fig(4, '/findings?status=false_positive'),
            stages: {
              focus: 0,
              stages: [
                {
                  key: 'scoping' as const,
                  state: 'warn' as const,
                  value: 0,
                  unit: 'count' as const,
                  drill: '/assets',
                },
                {
                  key: 'validate' as const,
                  state: 'not_measured' as const,
                  value: null,
                  unit: 'percent' as const,
                },
              ],
            },
          },
        }
      }
      case 'exposure.levers':
        return {
          ...base,
          shape: 'levers' as const,
          levers: {
            levers: [
              {
                kind: 'one_fix' as const,
                count: 27,
                assets: 14,
                title: 'Upgrade openssl',
                points: 70,
                effect: {
                  metric: 'exposure.priority_open',
                  before: 31,
                  after: 19,
                  unit: 'count' as const,
                },
                drill: '/remediation/suggestions',
              },
              {
                kind: 'blind_spot' as const,
                count: 50,
                points: 0,
                effect: {
                  metric: 'coverage.discovery',
                  before: 75,
                  after: 100,
                  unit: 'percent' as const,
                },
                drill: '/assets?coverage=uncovered',
              },
            ],
          },
        }
      case 'brief.weekly':
        return {
          ...base,
          shape: 'brief' as const,
          brief: {
            since: '2026-10-23T00:00:00Z',
            items: [
              {
                kind: 'change' as const,
                variant: 'down' as const,
                chips: [
                  { key: 'opened', value: 8 },
                  { key: 'fixed', value: 13 },
                ],
              },
              {
                kind: 'sla_due' as const,
                chips: [
                  { key: 'due_soon', value: 4, drill: '/findings?sla_status=warning&state=open' },
                  { key: 'past_sla', value: 10, drill: '/findings?sla_status=overdue&state=open' },
                ],
              },
            ],
          },
        }
      case 'exposure.kpis':
        return {
          ...base,
          shape: 'kpis' as const,
          kpis: {
            tiles: [
              {
                key: 'priority_open' as const,
                metric: 'exposure.priority_open',
                state: 'ready' as const,
                value: 31,
                previous: 43,
                unit: 'count' as const,
                polarity: 'lower_better' as const,
                drill: '/findings?priority_class=P0,P1&state=open',
              },
              {
                key: 'kev_open' as const,
                metric: 'intel.kev_open',
                state: 'ready' as const,
                value: 9,
                unit: 'count' as const,
                polarity: 'lower_better' as const,
                drill: '/findings?is_in_kev=true&state=open',
              },
              {
                key: 'sla_within' as const,
                metric: 'sla.within',
                state: 'ready' as const,
                value: 78,
                unit: 'percent' as const,
                polarity: 'higher_better' as const,
              },
              {
                key: 'time_to_fix' as const,
                metric: 'fix.time_to_fix',
                state: 'not_measured' as const,
                reason: 'too_few_fixed',
                value: null,
                unit: 'hours' as const,
                polarity: 'lower_better' as const,
              },
              {
                key: 'coverage' as const,
                metric: 'coverage.discovery',
                state: 'ready' as const,
                value: 91,
                unit: 'percent' as const,
                polarity: 'higher_better' as const,
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
        <DashboardFreshness kind="personal" data={data} />
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
