import { act, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { ExposureFlowViz, ringArcs } from '../exposure-flow-viz'
import { IntakeViz } from '../intake-viz'
import type { FlowResult, IntakeData, IntakeSourceRow } from '../types'

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

describe('ringArcs', () => {
  it('draws one arc per class with findings, the largest centred at the bottom', () => {
    const arcs = ringArcs(flow.classes)
    expect(arcs.map((a) => a.key)).toEqual(['P0', 'P1', 'P2', 'P3'])
    // P3 (the largest) is centred on 6 o'clock: its label sits straight below.
    const p3 = arcs[3]
    expect(Math.abs(p3.labelX)).toBeLessThan(0.01)
    expect(p3.labelY).toBeGreaterThan(0)
  })

  it('leaves out an empty class and draws nothing without findings', () => {
    expect(
      ringArcs([
        { key: 'P0', value: 0 },
        { key: 'P1', value: 5 },
      ]).map((a) => a.key)
    ).toEqual(['P1'])
    expect(ringArcs([{ key: 'P0', value: 0 }])).toEqual([])
  })
})

describe('ExposureFlowViz', () => {
  it('shows every figure as a link to the list it counts', () => {
    render(<ExposureFlowViz result={flow} scope="organization" />)
    expect(hrefOf(/^Actionable now 791/)).toBe(flow.actionable.drill)
    expect(hrefOf(/^Received 602$/)).toBe(intake.drill)
    expect(hrefOf(/^New or reopened 312$/)).toBe(intake.drill)
    expect(hrefOf(/^Open 791$/)).toBe(flow.open.drill)
    expect(hrefOf(/^Past SLA 43$/)).toBe(flow.past_sla.drill)
    expect(hrefOf(/^In progress 112$/)).toBe(flow.in_progress.drill)
    expect(hrefOf(/^Fixed 318$/)).toBe(flow.fixed.drill)
    expect(hrefOf(/^Accepted 22$/)).toBe(flow.accepted.drill)
    expect(hrefOf(/^False positive 97$/)).toBe(flow.false_positive.drill)
    expect(hrefOf(/^nuclei Sensor 402$/)).toBe(intake.sources[0].drill)
    expect(hrefOf('Mobilize: 78%')).toBe('/findings?state=open&sla_status=overdue')
    // The ring's arcs are focusable links with a sentence each.
    expect(
      screen.getByRole('link', { name: 'P0: 9 findings, 1% of actionable' })
    ).toBeInTheDocument()
    expect(screen.getByText('Organization figures')).toBeInTheDocument()
  })

  it('says how unhealthy sources are in words, not only colour', () => {
    render(<ExposureFlowViz result={flow} />)
    expect(screen.getByText(/Stale, last 3 days ago/)).toBeInTheDocument()
    expect(screen.getByText(/Failed/)).toBeInTheDocument()
    expect(screen.getAllByText('Unnamed tool').length).toBeGreaterThan(0)
  })

  it('lights a class on focus: centre swaps, the tooltip opens with its list, Escape closes it', async () => {
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

  it('opens the source tooltip on hover with its receipts', async () => {
    const user = userEvent.setup()
    render(<ExposureFlowViz result={flow} />)
    await user.hover(screen.getByRole('link', { name: /^nuclei Sensor 402$/ }))
    const tip = screen.getByRole('tooltip')
    expect(within(tip).getByText('nuclei: received')).toBeInTheDocument()
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
    expect(screen.queryByText('602')).not.toBeInTheDocument()
    expect(screen.getByText('Counts in your data scope')).toBeInTheDocument()
    expect(hrefOf(/^Actionable now 791/)).toBe(flow.actionable.drill)
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

  it('keeps the flow steps non-increasing and sets the stock apart', () => {
    render(<ExposureFlowViz result={seededFlow} />)
    const received = screen.getByRole('link', { name: /Received/ })
    const newOrReopened = screen.getByRole('link', { name: /New or reopened/ })
    expect(received).toHaveTextContent('1,634')
    expect(newOrReopened).toHaveTextContent('346')
    const actionable = screen.getByRole('link', { name: /Actionable now/ })
    expect(actionable).toHaveTextContent('760')
    expect(actionable).toHaveTextContent('open now, not part of the period')
  })
})
