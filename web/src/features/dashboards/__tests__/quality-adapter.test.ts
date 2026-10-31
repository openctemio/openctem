import { describe, expect, it } from 'vitest'
import { reasonKeyOf, unitOf, widgetModel } from '../api/widget-adapter'
import type { WidgetValue } from '../api/widget-data'
import type { WidgetSpec } from '../api/widget-spec'

const spec = (metric: string): WidgetSpec => ({
  v: 2,
  id: 'w_q',
  data: { kind: 'metric', metric, filter: {}, time: {} },
  viz: { type: 'bar', options: {} },
})

const base: WidgetValue = { id: 'w_q', index: 0, widget_type: 'metric', state: 'ready' }

function rowsOf(v: WidgetValue) {
  const m = widgetModel(v, spec(v.metric ?? ''), false)
  expect(m.state).toBe('ready')
  expect(m.result).toMatchObject({ shape: 'category', ordinal: true })
  return m.result && m.result.shape === 'category' ? m.result.rows : []
}

describe('closure quality, campaign and false-positive widgets', () => {
  it('closure rows are named by their key and keep the server order', () => {
    const rows = rowsOf({
      ...base,
      metric: 'findings.closure_quality',
      shape: 'category',
      category: {
        rows: [
          { key: 'closed_by_person', value: 4 },
          { key: 'closed_automatically', value: 9 },
          { key: 'reopened', value: 2 },
          { key: 'ready_to_close', value: 5, drill: '/findings/ready-to-close' },
        ],
        total: 20,
      },
    })
    expect(rows.map((r) => r.label_key)).toEqual([
      'dashboards.closure.closed_by_person',
      'dashboards.closure.closed_automatically',
      'dashboards.closure.reopened',
      'dashboards.closure.ready_to_close',
    ])
  })

  it('campaigns and tools show the server label as is, in percent', () => {
    const campaign: WidgetValue = {
      ...base,
      metric: 'remediation.campaign_progress',
      shape: 'category',
      category: {
        rows: [{ key: '7f1c', label: 'Q4 patching', value: 40, n: 10 }],
        total: 40,
      },
    }
    const rows = rowsOf(campaign)
    expect(rows[0]).toMatchObject({ key: '7f1c', label: 'Q4 patching', label_key: undefined })
    expect(unitOf(campaign)).toBe('percent')

    const tools = rowsOf({
      ...base,
      metric: 'detection.fp_rate_by_tool',
      shape: 'category',
      category: { rows: [{ key: 'nuclei', label: 'nuclei', value: 25, n: 40 }], total: 25 },
    })
    expect(tools[0]).toMatchObject({ label: 'nuclei', label_key: undefined })
  })

  it('maps the new empty reasons to their messages', () => {
    for (const r of ['no_closures', 'no_active_campaigns', 'too_few_closed', 'organization_only']) {
      expect(reasonKeyOf(r)).toBe(`dashboards.reason.${r}`)
    }
  })
})
