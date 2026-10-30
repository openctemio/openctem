import { describe, expect, it } from 'vitest'
import { flowPanelEligible, hasFlowWidget } from '../flow-panel'

const w = (metric: string) => ({
  widget_type: 'metric',
  x: 0,
  y: 0,
  w: 6,
  h: 2,
  config: { id: 'w_a', data: { kind: 'metric', metric } },
})

describe('flowPanelEligible', () => {
  it('only an explicit null, a non-empty layout and no flow', () => {
    expect(flowPanelEligible({ flow_panel_at: null, layout: [w('findings.open')] })).toBe(true)
    expect(flowPanelEligible({ flow_panel_at: undefined, layout: [w('findings.open')] })).toBe(
      false
    )
    expect(
      flowPanelEligible({ flow_panel_at: '2026-10-01T00:00:00Z', layout: [w('findings.open')] })
    ).toBe(false)
    expect(flowPanelEligible({ flow_panel_at: null, layout: [] })).toBe(false)
    expect(flowPanelEligible({ flow_panel_at: null, layout: [w('exposure.flow')] })).toBe(false)
  })
  it('finds the flow widget by metric', () => {
    expect(hasFlowWidget([w('findings.open'), w('exposure.flow')])).toBe(true)
    expect(hasFlowWidget(undefined)).toBe(false)
  })
})
