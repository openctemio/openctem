import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ExposureFlowViz } from '../exposure-flow-viz'
import { ringEdgeInset, ringSegments, type RingPart } from '../flow-rings'
import { IntakeViz } from '../intake-viz'
import type { FlowResult, IntakeData, IntakeSourceRow } from '../types'

// The tooltip popper measures itself; without this it throws when a click opens a tooltip.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const since = new Date(Date.now() - 30 * 86_400_000).toISOString()

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
    last_at: new Date().toISOString(),
    last_status: 'completed',
    health: 'ok',
    expected_every_seconds: 3600,
    drill: `/findings/imports?origin=${p.origin}&tool=${p.tool}`,
    ...p,
  }
}

const intake: IntakeData = {
  since,
  days: 30,
  sources: [
    source({ id: 'sensor:nuclei', tool: 'nuclei', origin: 'sensor', received: 402 }),
    source({
      id: 'connector:cloud',
      tool: 'cloud',
      origin: 'connector',
      received: 173,
      health: 'stale',
      last_at: new Date(Date.now() - 3 * 86_400_000).toISOString(),
    }),
    source({
      id: 'ci:unknown',
      tool: 'unknown',
      origin: 'ci',
      received: 27,
      health: 'failed',
      last_status: 'failed',
    }),
  ],
  totals: source({
    id: ':',
    tool: '',
    origin: '',
    received: 602,
    receipts: 9,
    still_detected: 924,
    created: 300,
    reopened: 12,
    suppressed: 8,
    not_stored: 12,
  }),
  noise: { received: 602, new: 312, merged: 278, suppressed: 8, not_stored: 12 },
  failing: 1,
  stale: 1,
  drill: '/findings/imports?since=x',
  false_positive: { value: 97, drill: '/findings?status=false_positive' },
}

const flow: FlowResult = {
  shape: 'flow',
  since,
  days: 30,
  intake,
  actionable: { value: 791, drill: '/findings?state=open&priority_class=P0,P1,P2,P3' },
  classes: [
    { key: 'P0', value: 9, drill: '/findings?state=open&priority_class=P0' },
    { key: 'P1', value: 82, drill: '/findings?state=open&priority_class=P1' },
    { key: 'P2', value: 260, drill: '/findings?state=open&priority_class=P2' },
    { key: 'P3', value: 440, drill: '/findings?state=open&priority_class=P3' },
  ],
  open: { value: 791, drill: '/findings?state=open' },
  severity: [
    { key: 'critical', value: 41, drill: '/findings?state=open&severity=critical' },
    { key: 'high', value: 150, drill: '/findings?state=open&severity=high' },
  ],
  past_sla: { value: 43, drill: '/findings?state=open&sla_status=overdue' },
  in_progress: { value: 112, drill: '/findings?status=in_progress' },
  fixed: { value: 318, drill: '/findings?status=resolved' },
  accepted: { value: 22, drill: '/findings?status=accepted' },
  false_positive: { value: 97, drill: '/findings?status=false_positive' },
  stages: {
    shape: 'stages',
    focus: 4,
    stages: [
      {
        key: 'scoping',
        label: 'Scoping',
        value: 12,
        state: 'good',
        drill: '/assets?is_crown_jewel=true',
      },
      {
        key: 'discovery',
        label: 'Discovery',
        value: 91,
        unit: 'percent',
        state: 'warn',
        drill: '/assets?coverage=uncovered',
      },
      {
        key: 'prioritize',
        label: 'Prioritize',
        value: 9,
        state: 'good',
        drill: '/findings?state=open&priority_class=P0',
      },
      { key: 'validate', label: 'Validate', value: null, unit: 'percent', state: 'unmeasured' },
      {
        key: 'mobilize',
        label: 'Mobilize',
        value: 78,
        unit: 'percent',
        state: 'crit',
        drill: '/findings?state=open&sla_status=overdue',
      },
    ],
  },
}

function hrefOf(name: RegExp | string): string | null {
  return screen.getByRole('link', { name }).getAttribute('href')
}

const part = (key: string, value: number): RingPart => ({ key, value, color: 'red', aria: key })

describe('ringSegments', () => {
  it('draws one segment per part with a value, the largest centred at the bottom', () => {
    const segs = ringSegments(
      flow.classes.map((c) => part(c.key ?? '', c.value)),
      92,
      18
    )
    expect(segs.map((x) => x.key)).toEqual(['P0', 'P1', 'P2', 'P3'])
    // P3 (the largest) is centred on 6 o'clock.
    const p3 = segs[3]
    expect(Math.abs((p3.a0 + p3.a1) / 2 - Math.PI)).toBeLessThan(1e-9)
  })

  it('keeps a visible gap after the round caps and a small part visible', () => {
    const r = 140
    const w = 12
    const segs = ringSegments([part('a', 1000), part('b', 1), part('c', 400)], r, w)
    for (let i = 0; i < segs.length; i++) {
      const next = segs[(i + 1) % segs.length]
      let gap = next.a0 - segs[i].a1
      if (gap < 0) gap += 2 * Math.PI
      // The gap minus both half-caps leaves about four viewBox units.
      expect(gap * r - w).toBeGreaterThan(3.9)
    }
    expect(segs[1].a1 - segs[1].a0).toBeGreaterThan(0.019)
  })

  it('leaves out an empty part, closes a single part, draws nothing without values', () => {
    expect(ringSegments([part('P0', 0), part('P1', 5)], 92, 18).map((x) => x.key)).toEqual(['P1'])
    expect(ringSegments([part('P1', 5)], 92, 18)[0].a1).toBeCloseTo(2 * Math.PI)
    expect(ringSegments([part('P0', 0)], 92, 18)).toEqual([])
  })

  it('puts the wire joints on the outer edge of the outer ring', () => {
    // Three rings: outer radius 140 + half of 12 = 146 of 160.
    expect(ringEdgeInset(3)).toBeCloseTo(14 / 320)
    expect(ringEdgeInset(1)).toBeCloseTo((160 - 139) / 320)
  })
})

/**
 * jsdom has no layout: the visual measures 0 px and takes the phone band.
 * `atWidth` gives every element a width so the wide band renders.
 */
function atWidth(width: number) {
  const spy = vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
    width,
    height: 400,
    top: 0,
    left: 0,
    right: width,
    bottom: 400,
    x: 0,
    y: 0,
    toJSON: () => ({}),
  } as DOMRect)
  return () => spy.mockRestore()
}

describe('ExposureFlowViz on a phone (narrow band)', () => {
  it('shows every figure as a link to the list it counts', () => {
    render(<ExposureFlowViz result={flow} scope="organization" />)
    expect(screen.getByTestId('exposure-flow')).toHaveAttribute('data-band', 'narrow')
    expect(hrefOf(/^Actionable now 791$/)).toBe(flow.actionable.drill)
    expect(hrefOf('P0: 9 actionable findings')).toBe(flow.classes[0].drill)
    expect(hrefOf('P3: 440 actionable findings')).toBe(flow.classes[3].drill)
    expect(hrefOf(/^602 findings received$/)).toBe(intake.drill)
    expect(hrefOf(/^312 new or reopened$/)).toBe(intake.drill)
    expect(hrefOf(/^924 still detected on import$/)).toBe(intake.drill)
    expect(hrefOf(/^8 removed by rules$/)).toBe(intake.drill)
    expect(hrefOf(/^Open 791$/)).toBe(flow.open.drill)
    expect(hrefOf(/^Past SLA 43$/)).toBe(flow.past_sla.drill)
    expect(hrefOf(/^In progress 112$/)).toBe(flow.in_progress.drill)
    expect(hrefOf(/^Fixed 318$/)).toBe(flow.fixed.drill)
    expect(hrefOf(/^Accepted 22$/)).toBe(flow.accepted.drill)
    expect(hrefOf(/^False positive 97$/)).toBe(flow.false_positive.drill)
    expect(hrefOf(/^nuclei Sensor 402 findings/)).toBe(intake.sources[0].drill)
    expect(hrefOf('Mobilize: 78% within SLA, Off track')).toBe(
      '/findings?state=open&sla_status=overdue'
    )
    expect(screen.getByText('Organization')).toBeInTheDocument()
  })

  it('puts the answer first: actionable, outcomes, stages, then sources; no ring', () => {
    render(<ExposureFlowViz result={flow} />)
    const order = [...screen.getByTestId('exposure-flow').querySelectorAll('[data-testid]')]
      .map((el) => el.getAttribute('data-testid'))
      .filter((id) =>
        ['flow-headline', 'flow-outcomes', 'flow-stages', 'flow-sources'].includes(id ?? '')
      )
    expect(order).toEqual(['flow-headline', 'flow-outcomes', 'flow-stages', 'flow-sources'])
    expect(screen.getByTestId('flow-priority-bar').querySelectorAll('[data-part]')).toHaveLength(4)
    expect(screen.queryByRole('group', { name: /by priority class/ })).not.toBeInTheDocument()
  })

  it('shows the same rings small beside the headline: decorative, a tap explains', () => {
    render(<ExposureFlowViz result={flow} />)
    const rings = within(screen.getByTestId('flow-headline')).getByTestId('flow-rings')
    expect(rings).toHaveAttribute('aria-hidden', 'true')
    expect(rings.querySelectorAll('[data-ring]')).toHaveLength(3)
    expect(rings.querySelector('[role="link"]')).toBeNull()
    const seg = rings.querySelector('[data-seg="p:P0"]') as Element
    fireEvent.pointerDown(seg, { pointerType: 'touch' })
    fireEvent.click(seg)
    expect(within(screen.getByRole('tooltip')).getByText('Actionable: P0')).toBeInTheDocument()
  })

  it('shows the actionable total once, without the old period caption', () => {
    render(<ExposureFlowViz result={{ ...flow, open: { value: 800, drill: flow.open.drill } }} />)
    expect(screen.getAllByText('791')).toHaveLength(1)
    expect(screen.queryByText(/not part of the period/)).not.toBeInTheDocument()
  })

  it('says how unhealthy sources are in words, not only colour', () => {
    render(<ExposureFlowViz result={flow} />)
    expect(screen.getByText(/Stale, last receipt 3 days ago/)).toBeInTheDocument()
    expect(screen.getByText(/Failed/)).toBeInTheDocument()
    expect(screen.getAllByText('Unnamed tool').length).toBeGreaterThan(0)
  })

  it('opens the source tooltip on hover with its receipts and its split', async () => {
    const user = userEvent.setup()
    render(<ExposureFlowViz result={flow} />)
    await user.hover(screen.getByRole('link', { name: /^nuclei Sensor 402 findings/ }))
    const tip = screen.getByRole('tooltip')
    expect(within(tip).getByText('nuclei')).toBeInTheDocument()
    expect(within(tip).getByText('Seen again')).toBeInTheDocument()
    expect(within(tip).getByText('Not stored')).toBeInTheDocument()
    expect(within(tip).getByRole('link', { name: 'View 3 receipts' })).toHaveAttribute(
      'href',
      intake.sources[0].drill
    )
  })

  it('shows why sources are missing for a scoped read, never organization volumes', () => {
    render(
      <ExposureFlowViz
        result={{ ...flow, intake: null, intake_reason_key: 'dashboards.reason.organization_only' }}
        scope="personal"
      />
    )
    expect(screen.queryByRole('link', { name: /^nuclei/ })).not.toBeInTheDocument()
    expect(screen.queryByText(/602/)).not.toBeInTheDocument()
    expect(screen.getByText('Your scope')).toBeInTheDocument()
    expect(hrefOf(/^Actionable now 791$/)).toBe(flow.actionable.drill)
  })

  it('never links an unsafe drill', () => {
    render(<ExposureFlowViz result={{ ...flow, fixed: { value: 3, drill: null } }} />)
    expect(screen.queryByRole('link', { name: /^Fixed 3$/ })).not.toBeInTheDocument()
  })

  it('has a table view with the same figures', async () => {
    const user = userEvent.setup()
    render(<ExposureFlowViz result={flow} />)
    await user.click(screen.getByRole('button', { name: 'Show table' }))
    const table = screen.getAllByRole('table')
    expect(table.length).toBeGreaterThanOrEqual(3)
    expect(screen.getByRole('row', { name: /P2 260/ })).toBeInTheDocument()
  })
})

describe('stages: one icon set, state in words, act-here apart', () => {
  it('keeps the focus stage icon in its own state colour and marks "Act here" separately', () => {
    render(<ExposureFlowViz result={flow} />)
    const stages = screen.getByTestId('flow-stages')
    const current = stages.querySelector('[aria-current="step"]') as HTMLElement
    expect(current).toHaveAttribute('data-state', 'crit')
    const icon = current.querySelector('svg[data-state]') as SVGElement
    expect(icon.getAttribute('class')).toContain('text-destructive')
    expect(icon.getAttribute('class')).not.toContain('signal')
    expect(within(current).getByTestId('stage-act-here')).toHaveTextContent('Act here')
    expect(within(current).getByText('Off track')).toBeInTheDocument()
  })

  it('names what each figure measures, so a count and a share never read as one unit', () => {
    render(<ExposureFlowViz result={flow} />)
    const stages = screen.getByTestId('flow-stages')
    expect(within(stages).getByText('crown jewels')).toBeInTheDocument()
    expect(within(stages).getByText('scanned')).toBeInTheDocument()
    expect(within(stages).getByText('open P0')).toBeInTheDocument()
    expect(within(stages).getByText('within SLA')).toBeInTheDocument()
    expect(within(stages).getByText('Not measured')).toBeInTheDocument()
  })
})

describe('sources: ranked bars by findings or assets, by tool or instance', () => {
  const now = new Date().toISOString()
  const withAssets: FlowResult = {
    ...flow,
    intake: {
      ...intake,
      sources: [
        source({
          id: 'sensor:nuclei',
          tool: 'nuclei',
          origin: 'sensor',
          received: 402,
          kind: 'detection',
          instances: [
            {
              id: 's1',
              kind: 'sensor',
              name: 'edge-01',
              received: 402,
              health: 'ok',
              last_at: now,
              sensor_href: '/sensors/s1',
            },
          ],
        }),
        source({
          id: 'sensor:subfinder',
          tool: 'subfinder',
          origin: 'sensor',
          received: 0,
          assets: 9000,
          kind: 'discovery',
          instances: [
            {
              id: 's1',
              kind: 'sensor',
              name: 'edge-01',
              received: 0,
              assets: 6000,
              health: 'ok',
              last_at: now,
              sensor_href: '/sensors/s1',
            },
            {
              id: 's2',
              kind: 'sensor',
              name: 'dc-02',
              received: 0,
              assets: 3000,
              health: 'failed',
              last_at: now,
              sensor_href: '/sensors/s2',
            },
          ],
        }),
        source({ id: 'sensor:dnsx', tool: 'dnsx', origin: 'sensor', received: 0, assets: 0 }),
        source({
          id: 'platform:version-match',
          tool: 'version-match',
          origin: 'platform',
          received: 59,
          kind: 'platform',
          instances: [
            {
              id: 'platform',
              kind: 'platform',
              name: 'Platform',
              received: 59,
              health: 'ok',
              last_at: now,
            },
          ],
        }),
      ],
    },
  }
  const ranked = () =>
    [...screen.getByTestId('ranked-bars').querySelectorAll('li[data-key]')].map((li) =>
      li.getAttribute('data-key')
    )

  beforeEach(() => {
    try {
      window.localStorage.clear()
    } catch {
      /* no storage */
    }
  })

  it('ranks by findings first and lists every source, the silent ones last', async () => {
    const user = userEvent.setup()
    render(<ExposureFlowViz result={withAssets} />)
    expect(ranked()).toEqual([
      's:sensor:nuclei',
      's:platform:version-match',
      's:sensor:dnsx',
      's:sensor:subfinder',
    ])
    expect(screen.getByTestId('ranked-zeros')).toHaveTextContent('Hide 2 with nothing')
    await user.click(screen.getByTestId('ranked-zeros'))
    expect(ranked()).toEqual(['s:sensor:nuclei', 's:platform:version-match'])
    expect(screen.getByTestId('ranked-zeros')).toHaveTextContent(
      '+2 sources with nothing in 30 days'
    )
    expect(hrefOf(/^version-match Platform 59 findings/)).toBe(withAssets.intake?.sources[3].drill)
  })

  it('re-ranks by assets, so a discovery tool is never shown as zero', async () => {
    const user = userEvent.setup()
    render(<ExposureFlowViz result={withAssets} />)
    await user.click(screen.getByRole('button', { name: 'Assets' }))
    expect(ranked()[0]).toBe('s:sensor:subfinder')
    expect(screen.getByRole('link', { name: /^subfinder Sensor 9,000 assets/ })).toBeInTheDocument()
    expect(screen.queryAllByTestId('rank-move')).toHaveLength(0)
  })

  it('groups by instance from the same read, a failing instance keeps its dot', async () => {
    const user = userEvent.setup()
    render(<ExposureFlowViz result={withAssets} />)
    await user.click(screen.getByRole('button', { name: 'Source instance' }))
    expect(ranked()).toEqual(['i:sensor:s1', 'i:platform:platform', 'i:sensor:s2'])
    const failing = screen.getByRole('link', { name: /^dc-02 Sensor 0 findings/ })
    expect(failing).toHaveAttribute('href', '/sensors/s2')
    expect(failing).toHaveAttribute('data-health', 'failed')
  })

  it('lists the instances that fed a tool in its tooltip, with a link to the sensor', async () => {
    const user = userEvent.setup()
    render(<ExposureFlowViz result={withAssets} />)
    await user.hover(screen.getByRole('link', { name: /^nuclei Sensor 402 findings/ }))
    const tip = screen.getByRole('tooltip')
    expect(within(tip).getByText('edge-01')).toBeInTheDocument()
    expect(within(tip).getByText('402 (100%)')).toBeInTheDocument()
    expect(within(tip).getByRole('link', { name: 'Per-sensor activity' })).toHaveAttribute(
      'href',
      '/sensors/s1'
    )
  })

  it('remembers the view on this browser and survives blocked storage', async () => {
    const user = userEvent.setup()
    const { unmount } = render(<ExposureFlowViz result={withAssets} />)
    await user.click(screen.getByRole('button', { name: 'Source instance' }))
    unmount()
    render(<ExposureFlowViz result={withAssets} />)
    expect(screen.getByRole('button', { name: 'Source instance' })).toHaveAttribute(
      'aria-pressed',
      'true'
    )
    cleanup()
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    render(<ExposureFlowViz result={withAssets} />)
    await user.click(screen.getByRole('button', { name: 'Assets' }))
    expect(ranked()[0]).toBe('s:sensor:subfinder')
    get.mockRestore()
    set.mockRestore()
  })

  it('hides the switches when no source carries assets or instances', () => {
    render(<ExposureFlowViz result={flow} />)
    expect(screen.queryByRole('group', { name: 'View' })).not.toBeInTheDocument()
  })
})

describe('ExposureFlowViz on a wide card', () => {
  let restore: () => void
  beforeEach(() => {
    restore = atWidth(1200)
  })
  afterEach(() => restore())

  it('keeps the ring, its arcs are links, the funnel has no actionable figure', () => {
    render(<ExposureFlowViz result={flow} />)
    expect(screen.getByTestId('exposure-flow')).toHaveAttribute('data-band', 'wide')
    expect(
      screen.getByRole('link', { name: 'P0: 9 findings, 1% of actionable' })
    ).toBeInTheDocument()
    expect(hrefOf(/^Findings received 602$/)).toBe(intake.drill)
    expect(hrefOf(/^New or reopened 312$/)).toBe(intake.drill)
    expect(hrefOf(/^Actionable now 791 by priority class$/)).toBe(flow.actionable.drill)
  })

  it('reads from the outside in: received by source, new by source, actionable by class', () => {
    render(<ExposureFlowViz result={flow} />)
    const rings = screen.getByRole('group', { name: /by source, actionable findings/ })
    expect(rings.querySelectorAll('[data-ring]')).toHaveLength(3)
    expect(rings.querySelectorAll('[data-testid="ring-track"]')).toHaveLength(3)
    expect(
      screen.getByRole('link', { name: 'nuclei: 402 findings received, 67% of received' })
    ).toBeInTheDocument()
    // created 20 + reopened 2 of the 312 new or reopened.
    expect(
      screen.getByRole('link', { name: 'nuclei: 22 new or reopened, 7% of new or reopened' })
    ).toBeInTheDocument()
    // The source keeps one colour on its row and both arcs.
    const row = screen.getByRole('link', { name: /^nuclei Sensor 402 findings/ })
    const bar = row.querySelector('[data-testid="ranked-bar"]') as HTMLElement
    const outer = rings.querySelector('[data-seg="s:sensor:nuclei"]')
    const middle = rings.querySelector('[data-seg="n:sensor:nuclei"]')
    expect(bar.style.background).toBe('var(--viz-cat-1)')
    expect(outer?.getAttribute('stroke')).toBe('var(--viz-cat-1)')
    expect(middle?.getAttribute('stroke')).toBe('var(--viz-cat-1)')
  })

  it('lights a source on either arc: its row and both arcs stay, the rest dims', () => {
    render(<ExposureFlowViz result={flow} />)
    const arc = screen.getByRole('link', { name: /^nuclei: 22 new or reopened/ })
    act(() => arc.focus())
    const tip = screen.getByRole('tooltip')
    expect(within(tip).getByText('Share of new or reopened')).toBeInTheDocument()
    expect(within(tip).getByText('7%')).toBeInTheDocument()
    expect(within(tip).getByRole('link', { name: 'View 3 receipts' })).toHaveAttribute(
      'href',
      intake.sources[0].drill
    )
    const dimmed = (sel: string) => !!document.querySelector(sel)?.closest('.opacity-30')
    expect(dimmed('[data-seg="s:sensor:nuclei"]')).toBe(false)
    expect(dimmed('[data-seg="n:sensor:nuclei"]')).toBe(false)
    expect(dimmed('[data-seg="s:connector:cloud"]')).toBe(true)
    expect(dimmed('[data-seg="p:P0"]')).toBe(true)
    const row = screen.getByRole('link', { name: /^nuclei Sensor 402 findings/ })
    expect(row.className).not.toContain('opacity-30')
  })

  it('an outer arc lights the middle arc of its source', () => {
    render(<ExposureFlowViz result={flow} />)
    act(() => screen.getByRole('link', { name: /^cloud: 173 findings received/ }).focus())
    const dimmed = (sel: string) => !!document.querySelector(sel)?.closest('.opacity-30')
    expect(dimmed('[data-seg="n:connector:cloud"]')).toBe(false)
    expect(dimmed('[data-seg="n:sensor:nuclei"]')).toBe(true)
    expect(within(screen.getByRole('tooltip')).getByText('Share of received')).toBeInTheDocument()
  })

  it('a focused source keeps its colour on its wire, the only wire that glows', () => {
    render(<ExposureFlowViz result={flow} />)
    act(() => screen.getByRole('link', { name: /^nuclei Sensor 402 findings/ }).focus())
    const wire = (k: string) =>
      document.querySelector(`[data-wire-key="w:s:${k}"] path`) as SVGPathElement
    const bar = screen
      .getByRole('link', { name: /^nuclei Sensor 402 findings/ })
      .querySelector('[data-testid="ranked-bar"]') as HTMLElement
    const arc = document.querySelector('[data-seg="s:sensor:nuclei"]')
    // One source, one colour: bar, arc and wire.
    expect(wire('sensor:nuclei').getAttribute('stroke')).toBe(bar.style.background)
    expect(wire('sensor:nuclei').getAttribute('stroke')).toBe(arc?.getAttribute('stroke'))
    expect(wire('sensor:nuclei').style.filter).toContain('drop-shadow')
    expect(wire('connector:cloud').getAttribute('stroke')).not.toBe('var(--viz-cat-1)')
    expect(wire('connector:cloud').style.filter).toBe('')
    expect(document.querySelectorAll('[data-wire-key] path[style*="drop-shadow"]')).toHaveLength(1)
  })

  it('draws a wire proportional to its volume, 1 to 6 px', async () => {
    const { wireWidth } = await import('../flow-parts')
    expect(wireWidth(100, 100)).toBe(6)
    expect(wireWidth(50, 100)).toBe(3.5)
    expect(wireWidth(0, 100)).toBe(1)
  })

  it('shows each outcome as a box, its label above its figure', () => {
    render(<ExposureFlowViz result={flow} />)
    const open = within(screen.getByTestId('flow-outcomes')).getByRole('link', {
      name: /^Open 791/,
    })
    const [label, figure] = [...open.children] as HTMLElement[]
    expect(label).toHaveTextContent('Open')
    expect(figure).toHaveTextContent('791')
  })

  it('frames the sources and the outcomes alike: one thin dashed frame each', () => {
    render(<ExposureFlowViz result={flow} />)
    for (const id of ['flow-sources', 'flow-outcomes']) {
      const cls = screen.getByTestId(id).className
      expect(cls).toContain('@min-[660px]:border-dashed')
      expect(cls).toContain('@min-[660px]:border-border-strong')
      expect(cls).toContain('@min-[660px]:rounded-lg')
      expect(cls).toContain('@min-[660px]:p-1.5')
    }
  })

  it('a funnel figure lights its whole ring', () => {
    render(<ExposureFlowViz result={flow} />)
    act(() => screen.getByRole('link', { name: /^Findings received 602$/ }).focus())
    const dimmed = (sel: string) => !!document.querySelector(sel)?.closest('.opacity-30')
    expect(dimmed('[data-seg="s:sensor:nuclei"]')).toBe(false)
    expect(dimmed('[data-seg="s:ci:unknown"]')).toBe(false)
    expect(dimmed('[data-seg="n:sensor:nuclei"]')).toBe(true)
  })

  it('a scoped read draws the actionable ring alone, never organization volumes', () => {
    render(<ExposureFlowViz result={{ ...flow, intake: null }} />)
    const rings = screen.getByRole('group', { name: 'Actionable findings by priority class' })
    expect(rings.querySelectorAll('[data-ring]')).toHaveLength(1)
    expect(rings.querySelector('[data-seg^="s:"]')).toBeNull()
  })

  it('lights a class on focus: centre swaps, the tooltip opens with its list, Escape closes it', () => {
    render(<ExposureFlowViz result={flow} />)
    const arc = screen.getByRole('link', { name: 'P0: 9 findings, 1% of actionable' })
    act(() => arc.focus())
    expect(screen.getByTestId('flow-centre')).toHaveTextContent('9')
    const tip = screen.getByRole('tooltip')
    expect(arc).toHaveAttribute('aria-describedby', tip.id)
    expect(within(tip).getByText('Actionable: P0')).toBeInTheDocument()
    expect(within(tip).getByRole('link', { name: 'View 9 findings' })).toHaveAttribute(
      'href',
      flow.classes[0].drill
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
    expect(screen.getByTestId('flow-centre')).toHaveTextContent('791')
  })
})

describe('IntakeViz', () => {
  it('splits received into parts that sum to it, each opening the receipts', () => {
    render(<IntakeViz result={{ shape: 'intake', intake }} />)
    const n = intake.noise
    // New or reopened is the receipt list's New plus Reopened; suppressed
    // is inside it, so the three parts sum to received.
    expect(n.new + n.merged + n.not_stored).toBe(n.received)
    expect(n.new).toBe(intake.totals.created + intake.totals.reopened)
    expect(hrefOf('Merged: 278')).toBe(intake.drill)
    expect(hrefOf('of which suppressed by rules: 8')).toBe(intake.drill)
    expect(screen.getByText('298 noise removed')).toBeInTheDocument()
    expect(hrefOf('97 findings closed as false positive')).toBe(intake.false_positive.drill)
  })

  it('lists every source with its health and lights its summary on hover', async () => {
    const user = userEvent.setup()
    render(<IntakeViz result={{ shape: 'intake', intake }} />)
    expect(screen.getByText('1 failing')).toBeInTheDocument()
    expect(screen.getByText('1 stale')).toBeInTheDocument()
    expect(hrefOf('602 findings received')).toBe(intake.drill)
    await user.hover(screen.getByRole('link', { name: /^cloud Connector/ }))
    // The summary shows the hovered source.
    expect(screen.getByRole('link', { name: '173 findings received' })).toHaveAttribute(
      'href',
      intake.sources[1].drill
    )
    expect(screen.getByRole('tooltip')).toBeInTheDocument()
  })
})

// The seeded organization of the 2026-10-25 screenshots: 1,634 findings
// received, 346 new, 83 of them closed on arrival by a rule, 760 open now.
// Every figure is what the receipt list shows for the same filter, and the
// funnel's flow steps never grow; the stock is set apart.
describe('one definition per figure (count equals the list it opens)', () => {
  const seeded: IntakeData = {
    ...intake,
    sources: [
      source({
        id: 'sensor:a',
        tool: 'a',
        origin: 'sensor',
        received: 1634,
        created: 346,
        reopened: 0,
        suppressed: 83,
      }),
    ],
    totals: source({
      id: ':',
      tool: '',
      origin: '',
      received: 1634,
      created: 346,
      reopened: 0,
      suppressed: 83,
      not_stored: 5,
    }),
    noise: { received: 1634, new: 346, merged: 1283, suppressed: 83, not_stored: 5 },
  }
  const seededFlow: FlowResult = {
    ...flow,
    intake: seeded,
    actionable: { value: 760, drill: flow.actionable.drill },
  }

  it('shows the same new figure in the summary, the headline and the funnel', () => {
    const t = seeded.totals
    expect(seeded.noise.new).toBe(t.created + t.reopened)
    expect(seeded.noise.new + seeded.noise.merged + seeded.noise.not_stored).toBe(
      seeded.noise.received
    )
    render(<IntakeViz result={{ shape: 'intake', intake: seeded }} />)
    expect(screen.getByText('+346')).toBeInTheDocument()
    expect(hrefOf('New or reopened: 346')).toBe(seeded.drill)
    expect(screen.queryByText('263')).not.toBeInTheDocument()
  })

  it('keeps the flow steps non-increasing and shows the stock once', () => {
    const restore = atWidth(1200)
    render(<ExposureFlowViz result={seededFlow} />)
    const received = screen.getByRole('link', { name: /Findings received/ })
    const newOrReopened = screen.getByRole('link', { name: /^New or reopened/ })
    expect(received).toHaveTextContent('1,634')
    expect(newOrReopened).toHaveTextContent('346')
    expect(screen.getAllByText('760')).toHaveLength(1)
    expect(screen.queryByText(/not part of the period/)).not.toBeInTheDocument()
    restore()
  })
})

describe('flow layout bands', () => {
  it('follow the visual’s own width: one column, then core and outcomes, then three columns', async () => {
    const { flowBand, FLOW_MID, FLOW_WIDE } = await import('../flow-parts')
    expect(flowBand(0)).toBe('narrow')
    expect(flowBand(FLOW_MID - 1)).toBe('narrow')
    expect(flowBand(FLOW_MID)).toBe('mid')
    expect(flowBand(FLOW_WIDE - 1)).toBe('mid')
    expect(flowBand(FLOW_WIDE)).toBe('wide')
  })

  it('the container query classes use the same widths as the bands', async () => {
    const fs = await import('node:fs')
    const path = await import('node:path')
    const { FLOW_MID, FLOW_WIDE } = await import('../flow-parts')
    for (const file of ['exposure-flow-viz.tsx', 'intake-viz.tsx']) {
      const src = fs.readFileSync(path.join(__dirname, '..', file), 'utf8')
      const used = [...src.matchAll(/@min-\[(\d+)px\]/g)].map((m) => Number(m[1]))
      for (const w of used) expect([FLOW_MID, FLOW_WIDE, 420, 1100]).toContain(w)
      expect(used).toContain(FLOW_MID)
    }
  })

  it('an unhealthy source says so on its own row, under its name', () => {
    const { container } = render(<IntakeViz result={{ shape: 'intake', intake }} />)
    const note = screen.getAllByText(/Stale, last|Failed/)[0]
    const row = note.closest('a')
    expect(row).not.toBeNull()
    // The note sits in the name block, not beside the count at the far edge.
    expect(row?.querySelector('[data-wire-out]')?.contains(note)).toBe(false)
    expect(container.querySelector('[data-band]')).toHaveAttribute('data-band', 'narrow')
  })
})
