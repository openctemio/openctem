import { describe, expect, it } from 'vitest'
import { reasonKeyOf, widgetModel } from '../api/widget-adapter'
import type { WidgetValue } from '../api/widget-data'
import type { WidgetSpec } from '../api/widget-spec'

const spec = (metric: string): WidgetSpec => ({
  v: 2,
  id: 'w_b',
  data: { kind: 'metric', metric, filter: {}, time: {} },
  viz: { type: 'bar', options: {} },
})

const base: WidgetValue = { id: 'w_b', index: 0, widget_type: 'metric', state: 'ready' }

describe('breakdown widgets', () => {
  it('certificate bands are named by the band and keep their order', () => {
    const v: WidgetValue = {
      ...base,
      metric: 'certificates.expiry',
      shape: 'category',
      category: {
        rows: [
          { key: 'expired', value: 2, drill: '/assets?types=certificate&expires_before=x' },
          { key: 'within_7d', value: 0 },
          { key: 'within_30d', value: 5 },
          { key: 'within_90d', value: 11 },
        ],
        total: 18,
      },
    }
    const m = widgetModel(v, spec('certificates.expiry'), false)
    expect(m.state).toBe('ready')
    expect(m.result).toMatchObject({ shape: 'category', ordinal: true })
    const rows = m.result && m.result.shape === 'category' ? m.result.rows : []
    expect(rows.map((r) => r.label_key)).toEqual([
      'dashboards.band.expired',
      'dashboards.band.within_7d',
      'dashboards.band.within_30d',
      'dashboards.band.within_90d',
    ])
  })

  it('new assets are named by asset type and are not ordinal', () => {
    const v: WidgetValue = {
      ...base,
      metric: 'surface.new_assets',
      shape: 'category',
      category: {
        rows: [
          { key: 'domain', value: 3, previous: 1 },
          { key: 'ip_address', value: 0, previous: 4 },
        ],
        total: 3,
      },
    }
    const m = widgetModel(v, spec('surface.new_assets'), false)
    const r = m.result
    expect(r).toMatchObject({ shape: 'category', ordinal: false })
    const rows = r && r.shape === 'category' ? r.rows : []
    expect(rows[0]).toMatchObject({ label_key: 'assets.typeLabel.domain', previous: 1 })
    expect(rows[1].label_key).toBe('assets.typeLabel.ip_address')
  })

  it('no certificate in scope is the compact empty state, with its reason', () => {
    const v: WidgetValue = {
      ...base,
      metric: 'certificates.expiry',
      state: 'not_measured',
      reason: 'no_certificates',
    }
    const m = widgetModel(v, spec('certificates.expiry'), false)
    // Nothing has come in yet: the one compact empty state, never a "—".
    expect(m.state).toBe('no_data_yet')
    expect(m.reasonKey).toBe('dashboards.reason.no_certificates')
    expect(reasonKeyOf('no_certificates')).toBe('dashboards.reason.no_certificates')
  })

  it('emerging threats are named by alert level and keep the level order', () => {
    const v: WidgetValue = {
      ...base,
      metric: 'intel.emerging_threats',
      shape: 'category',
      category: {
        rows: [
          { key: 'immediate', value: 2, drill: '/emerging-threats?level=immediate&state=open' },
          { key: 'digest', value: 0 },
          { key: 'listed', value: 3, drill: '/emerging-threats?level=listed&state=open' },
        ],
        total: 5,
      },
    }
    const m = widgetModel(v, spec('intel.emerging_threats'), false)
    expect(m.result).toMatchObject({ shape: 'category', ordinal: true, total: 5 })
    const rows = m.result && m.result.shape === 'category' ? m.result.rows : []
    expect(rows.map((r) => r.label_key)).toEqual([
      'emergingThreats.level.immediate',
      'emergingThreats.level.digest',
      'emergingThreats.level.listed',
    ])
  })

  it('emerging threats without any alert, and a module that is off, have their reasons', () => {
    const m = widgetModel(
      {
        ...base,
        metric: 'intel.emerging_threats',
        state: 'not_measured',
        reason: 'no_threat_alerts',
      },
      spec('intel.emerging_threats'),
      false
    )
    expect(m.state).toBe('not_measured')
    expect(m.reasonKey).toBe('dashboards.reason.no_threat_alerts')
    expect(reasonKeyOf('module_off')).toBe('dashboards.reason.module_off')
  })
})
