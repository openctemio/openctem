import { describe, expect, it } from 'vitest'
import en from '@/lib/i18n/dictionaries/en/dashboards.json'
import vi from '@/lib/i18n/dictionaries/vi/dashboards.json'
import type { WidgetSpec } from '../api/widget-spec'
import { defaultWidgetTitle } from '../metrics'

const dict =
  (d: Record<string, string>) =>
  (key: string, fallback?: string, vars?: Record<string, string | number>) =>
    (d[key] ?? fallback ?? key).replace(/\{(\w+)\}/g, (_, k) => String(vars?.[k] ?? `{${k}}`))

const spec = (metric: string, group_by?: string[]) =>
  ({ data: { kind: 'metric', metric, filter: {}, time: {}, group_by } }) as unknown as WidgetSpec

describe('default widget title', () => {
  it('is the metric name without a group-by or with the metric default', () => {
    expect(defaultWidgetTitle(spec('findings.open'), dict(en))).toBe('Open findings')
    expect(defaultWidgetTitle(spec('findings.age_bands', ['severity', 'age_band']), dict(en))).toBe(
      'Open findings by age'
    )
  })

  it('names the group-by so two widgets of one metric are told apart', () => {
    expect(defaultWidgetTitle(spec('findings.open', ['severity']), dict(en))).toBe(
      'Open findings by severity'
    )
    expect(defaultWidgetTitle(spec('findings.open', ['sla_state']), dict(en))).toBe(
      'Open findings by SLA state'
    )
    expect(defaultWidgetTitle(spec('fix.time_to_fix', ['priority_class']), dict(vi))).toMatch(
      / theo mức ưu tiên$/
    )
  })

  it('every dimension has its in-title name in both catalogs', () => {
    for (const d of [
      'severity',
      'priority_class',
      'source',
      'sla_state',
      'age_band',
      'kev',
      'reachable',
      'asset_group',
    ]) {
      expect((en as Record<string, string>)[`dashboards.dimension.${d}.inTitle`]).toBeTruthy()
      expect((vi as Record<string, string>)[`dashboards.dimension.${d}.inTitle`]).toBeTruthy()
    }
  })
})
