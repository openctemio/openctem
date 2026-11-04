import { describe, expect, it } from 'vitest'
import { reasonKeyOf, widgetModel } from '../api/widget-adapter'
import type { WidgetValue } from '../api/widget-data'
import type { WidgetSpec } from '../api/widget-spec'
import { skeletonFor } from '../metrics'

const spec: WidgetSpec = {
  v: 2,
  id: 'w_p',
  data: { kind: 'metric', metric: 'surface.posture', filter: {}, time: {} },
  viz: { type: 'posture', options: {} },
}

const base: WidgetValue = {
  id: 'w_p',
  index: 0,
  widget_type: 'metric',
  state: 'ready',
  metric: 'surface.posture',
  shape: 'posture',
}

describe('posture widget', () => {
  it('maps the posture value', () => {
    const v: WidgetValue = {
      ...base,
      drill: '/attack-surface/posture',
      posture: {
        score: 81,
        grade: 'B',
        assets: 40,
        next_grade: 'A',
        next_floor: 90,
        fix_steps: 2,
        categories: [{ category: 'vulnerabilities', max: 35, deduction: 8.4, issues: 4 }],
      },
    }
    const m = widgetModel(v, spec, false)
    expect(m.state).toBe('ready')
    expect(m.result).toMatchObject({
      shape: 'posture',
      score: 81,
      grade: 'B',
      next_grade: 'A',
      fix_steps: 2,
      categories: [{ category: 'vulnerabilities', deduction: 8.4 }],
    })
  })

  it('has its own reasons and a stat skeleton', () => {
    expect(reasonKeyOf('no_surface')).toBe('dashboards.reason.no_surface')
    expect(reasonKeyOf('posture_building')).toBe('dashboards.reason.posture_building')
    expect(skeletonFor('posture')).toBe('stat')
  })
})
