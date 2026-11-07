import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ExposureFlowViz } from '../exposure-flow-viz'
import { FLOW_FAST_S, FLOW_SLOW_S, flowDuration } from '../flow-parts'
import { IntakeViz } from '../intake-viz'
import { groupByInstance, sourceWires } from '../source-view'
import type { FlowResult, IntakeData, IntakeSourceRow } from '../types'

/**
 * The wire model of the connected visuals (exposure flow, intake panel): one
 * wire per shown source row in either grouping, carrying findings received
 * whatever the bars rank by; the travelling light's speed follows the volume
 * on a log scale, there is none for nothing received, none under reduced
 * motion, and it pauses off screen or in a hidden tab.
 */

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const now = new Date().toISOString()
const t = (_k: string, fallback?: string) => fallback ?? _k

function source(
  p: Partial<IntakeSourceRow> & Pick<IntakeSourceRow, 'id' | 'tool' | 'origin'>
): IntakeSourceRow {
  return {
    receipts: 3,
    received: 100,
    created: 20,
    still_detected: 70,
    reopened: 2,
    closed: 1,
    suppressed: 4,
    not_stored: 3,
    last_at: now,
    last_status: 'completed',
    health: 'ok',
    expected_every_seconds: 3600,
    drill: `/findings/imports?origin=${p.origin}&tool=${p.tool}`,
    ...p,
  }
}

// A sensor that runs a scanner (findings) and a discovery sensor that only
// found assets: the owner's case, 1,281 assets and 0 findings received.
const sources: IntakeSourceRow[] = [
  source({
    id: 'sensor:nuclei',
    tool: 'nuclei',
    origin: 'sensor',
    received: 400,
    assets: 0,
    instances: [
      {
        id: 'scan-1',
        kind: 'sensor',
        name: 'scan-sensor',
        received: 400,
        assets: 0,
        health: 'ok',
        last_at: now,
      },
    ],
  }),
  source({
    id: 'sensor:subfinder',
    tool: 'subfinder',
    origin: 'sensor',
    received: 0,
    created: 0,
    assets: 1281,
    kind: 'discovery',
    instances: [
      {
        id: 'edge-1',
        kind: 'sensor',
        name: 'edge-sensor',
        received: 0,
        assets: 1281,
        health: 'ok',
        last_at: now,
      },
    ],
  }),
]

const totals = source({ id: ':', tool: '', origin: '', received: 400, receipts: 6 })
const intake: IntakeData = {
  since: now,
  days: 30,
  sources,
  totals,
  noise: { received: 400, new: 120, merged: 270, suppressed: 4, not_stored: 6 },
  failing: 0,
  stale: 0,
  drill: '/findings/imports',
  false_positive: { value: 3, drill: '/findings?status=false_positive' },
}

const fig = (value: number) => ({ value, drill: '/findings' })
const flow: FlowResult = {
  shape: 'flow',
  since: now,
  days: 30,
  intake,
  actionable: fig(50),
  classes: [{ key: 'P1', value: 50, drill: '/findings?priority_class=P1' }],
  open: fig(90),
  severity: [{ key: 'high', value: 90, drill: '/findings?severity=high' }],
  past_sla: fig(4),
  in_progress: fig(10),
  fixed: fig(30),
  accepted: fig(2),
  false_positive: fig(3),
  stages: null,
}

const box = {
  width: 1200,
  height: 400,
  top: 0,
  left: 0,
  right: 1200,
  bottom: 400,
  x: 0,
  y: 0,
  toJSON: () => ({}),
} as DOMRect

function setView(measure: 'findings' | 'assets', group: 'tool' | 'instance') {
  window.localStorage.setItem('openctem.dashboard.flow.sources', JSON.stringify({ measure, group }))
}

function mockReducedMotion(reduce: boolean) {
  vi.spyOn(window, 'matchMedia').mockImplementation(
    (q: string) =>
      ({
        matches: reduce && q.includes('prefers-reduced-motion'),
        media: q,
        onchange: null,
        addEventListener: () => {},
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
        dispatchEvent: () => false,
      }) as MediaQueryList
  )
}

const wire = (k: string) => document.querySelector(`[data-wire-key="${k}"]`)
const sourceWireKeys = () =>
  [...document.querySelectorAll('[data-wire-key^="w:s:"],[data-wire-key^="w:i:"]')].map((g) =>
    g.getAttribute('data-wire-key')
  )

beforeEach(() => {
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue(box)
  window.localStorage.clear()
  // jsdom has a matchMedia stub or none at all; give every test the same one.
  if (!window.matchMedia) {
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      writable: true,
      value: () => ({}),
    })
  }
  mockReducedMotion(false)
})
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('flowDuration: speed by volume, log-scaled', () => {
  it('has no light for nothing received', () => {
    expect(flowDuration(0, 100)).toBeNull()
    expect(flowDuration(-1, 100)).toBeNull()
  })
  it('is fastest for the largest and slows to the floor for the smallest', () => {
    expect(flowDuration(1000, 1000)).toBe(FLOW_FAST_S)
    expect(flowDuration(1, 1)).toBe(FLOW_FAST_S)
    const tiny = flowDuration(1, 1_000_000)!
    expect(tiny).toBeLessThanOrEqual(FLOW_SLOW_S)
    expect(tiny).toBeGreaterThan(FLOW_SLOW_S - 0.25)
  })
  it('grows monotonically and logarithmically, never linearly', () => {
    const d = [1, 10, 100, 1000, 10000].map((v) => flowDuration(v, 10000)!)
    for (let i = 1; i < d.length; i++) expect(d[i]).toBeLessThan(d[i - 1])
    // A tenth of the largest is still well past the middle of the speed range.
    expect(flowDuration(1000, 10000)!).toBeLessThan((FLOW_SLOW_S + FLOW_FAST_S) / 2)
  })
})

describe('sourceWires: one wire per row, carrying findings', () => {
  it('keys tool rows by source and carries findings received, not assets', () => {
    const { wires, max } = sourceWires(sources, groupByInstance(t, sources), 'tool')
    expect(wires.map((w) => w.key)).toEqual(['s:sensor:nuclei', 's:sensor:subfinder'])
    expect(wires.map((w) => w.received)).toEqual([400, 0])
    expect(wires[0].sourceId).toBe('sensor:nuclei')
    expect(max).toBe(400)
  })
  it('keys instance rows by instance (no source colour)', () => {
    const { wires } = sourceWires(sources, groupByInstance(t, sources), 'instance')
    expect(wires.map((w) => w.key)).toEqual(['i:sensor:scan-1', 'i:sensor:edge-1'])
    expect(wires.map((w) => w.received)).toEqual([400, 0])
    expect(wires.every((w) => w.sourceId === undefined)).toBe(true)
  })
  it('keeps max at least 1 when nothing was received', () => {
    const none = sources.map((s) => ({ ...s, received: 0 }))
    expect(sourceWires(none, [], 'tool').max).toBe(1)
  })
})

describe('Exposure flow: every shown source row has its wire', () => {
  it('draws the instance rows too, a thin dashed still wire for the assets-only sensor', async () => {
    setView('assets', 'instance')
    render(<ExposureFlowViz result={flow} />)
    await waitFor(() => expect(sourceWireKeys()).toHaveLength(2))
    expect(sourceWireKeys()).toEqual(['w:i:sensor:scan-1', 'w:i:sensor:edge-1'])
    const silent = wire('w:i:sensor:edge-1')!
    expect(silent.getAttribute('data-wire-motion')).toBe('off')
    expect(silent.querySelector('path')!.getAttribute('stroke-dasharray')).toBe('4 4')
    expect(silent.querySelector('path')!.getAttribute('stroke-width')).toBe('1')
    expect(silent.querySelector('.animate-flow-light')).toBeNull()
    const busy = wire('w:i:sensor:scan-1')!
    expect(busy.getAttribute('data-wire-motion')).toBe('on')
    expect(busy.querySelector('path')!.getAttribute('stroke-width')).toBe('6')
  })

  it('says, ranked by assets, that the wires carry findings only', async () => {
    setView('assets', 'tool')
    render(<ExposureFlowViz result={flow} />)
    expect(await screen.findByTestId('source-measure-note')).toHaveTextContent(
      'Lines carry findings only'
    )
    // The row shows the assets, the wire stays at the findings (none).
    expect(wire('w:s:sensor:subfinder')!.getAttribute('data-wire-motion')).toBe('off')
  })

  it('shows no note when ranked by findings', async () => {
    setView('findings', 'instance')
    render(<ExposureFlowViz result={flow} />)
    await waitFor(() => expect(sourceWireKeys()).toHaveLength(2))
    expect(screen.queryByTestId('source-measure-note')).toBeNull()
  })

  it('sets the light speed from the volume on the shared wire', async () => {
    render(<ExposureFlowViz result={flow} />)
    await waitFor(() => expect(wire('w:s:sensor:nuclei')).not.toBeNull())
    const light = wire('w:s:sensor:nuclei')!.querySelector<SVGPathElement>('.animate-flow-light')!
    expect(light.style.animationDuration).toBe(`${FLOW_FAST_S}s`)
  })
})

describe('Intake panel wires carry findings, not assets', () => {
  it('keeps the assets-only source a thin dashed wire when ranked by assets', async () => {
    setView('assets', 'tool')
    // Both rows listed when ranked by assets (a row with no assets folds away).
    const withAssets = {
      ...intake,
      sources: [{ ...sources[0], assets: 5 }, sources[1]],
    }
    render(<IntakeViz result={{ shape: 'intake', intake: withAssets }} />)
    await waitFor(() => expect(wire('w:s:sensor:subfinder')).not.toBeNull())
    const silent = wire('w:s:sensor:subfinder')!
    expect(silent.getAttribute('data-wire-motion')).toBe('off')
    expect(silent.querySelector('path')!.getAttribute('stroke-width')).toBe('1')
    expect(wire('w:s:sensor:nuclei')!.getAttribute('data-wire-motion')).toBe('on')
  })
})

describe('reduced motion and pausing', () => {
  it('draws no light at all under prefers-reduced-motion: reduce', async () => {
    mockReducedMotion(true)
    render(<ExposureFlowViz result={flow} />)
    await waitFor(() => expect(wire('w:s:sensor:nuclei')).not.toBeNull())
    expect(document.querySelectorAll('.animate-flow-light')).toHaveLength(0)
    for (const g of document.querySelectorAll('[data-wire-key]')) {
      expect(g.getAttribute('data-wire-motion')).toBe('off')
    }
    // Width still carries the volume.
    expect(wire('w:s:sensor:nuclei')!.querySelector('path')!.getAttribute('stroke-width')).toBe('6')
  })

  it('pauses the layer while it is off screen', async () => {
    let fire: (visible: boolean) => void = () => {}
    vi.stubGlobal(
      'IntersectionObserver',
      class {
        constructor(cb: (e: Array<{ isIntersecting: boolean }>) => void) {
          fire = (visible) => cb([{ isIntersecting: visible }])
        }
        observe() {}
        disconnect() {}
      }
    )
    render(<ExposureFlowViz result={flow} />)
    const layer = await screen.findByTestId('flow-wires')
    expect(layer).not.toHaveAttribute('data-flow-paused')
    act(() => fire(false))
    expect(layer).toHaveAttribute('data-flow-paused')
    act(() => fire(true))
    expect(layer).not.toHaveAttribute('data-flow-paused')
  })

  it('pauses the layer while the tab is hidden', async () => {
    render(<ExposureFlowViz result={flow} />)
    const layer = await screen.findByTestId('flow-wires')
    const state = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden')
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'))
    })
    expect(layer).toHaveAttribute('data-flow-paused')
    state.mockReturnValue('visible')
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'))
    })
    expect(layer).not.toHaveAttribute('data-flow-paused')
  })
})
