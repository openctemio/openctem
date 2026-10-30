import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { RunMap as RunMapData, RunTask } from '@/lib/api/generated'

const get = vi.fn()
vi.mock('@/lib/api/client', () => ({ get: (url: string) => get(url) }))

// The run's change notices: the test drives them by hand.
const channels: { channelType: string; channelId: string | null; onData?: (d: unknown) => void }[] =
  []
vi.mock('@/hooks/use-websocket', () => ({
  useChannel: (opts: {
    channelType: string
    channelId: string | null
    onData?: (d: unknown) => void
  }) => {
    channels.push(opts)
    return { data: null, isSubscribed: true, clearData: () => {} }
  },
}))

import { RunMap } from '../run-map'

const data: RunMapData = {
  run_id: 'r1',
  status: 'running',
  scan_workflow_version: 2,
  nodes: [
    {
      step_key: 'subdomains',
      name: 'Subdomains',
      depends_on: [],
      state: 'succeeded',
      findings: 0,
      chunks: { total: 1, queued: 0, running: 0, completed: 1, failed: 0 },
      outputs: { total: 312, by_type: { domain: 312 } },
    },
    {
      step_key: 'probe',
      name: 'Probe',
      depends_on: ['subdomains'],
      state: 'waiting',
      reason: 'waiting_for_sensor',
      findings: 0,
      chunks: { total: 2, queued: 2, running: 0, completed: 0, failed: 0 },
      outputs: { total: 0, by_type: {} },
    },
  ],
  edges: [{ from: 'subdomains', to: 'probe', count: 312 }],
}

const tasks = [
  {
    id: 't1',
    step_key: 'probe',
    tool: 'httpx',
    status: 'queued',
    targets: 40,
    attempts: 0,
    created_at: '2026-10-08T06:00:00Z',
  },
  {
    id: 't2',
    step_key: 'subdomains',
    tool: 'subfinder',
    status: 'completed',
    targets: 1,
    attempts: 1,
    created_at: '2026-10-08T06:00:00Z',
  },
] as RunTask[]

const renderMap = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <RunMap runId="r1" tasks={tasks} />
    </SWRConfig>
  )

/** A step card: a button named "<name>: <state>. Open the step". */
const stepButton = (name: string) => screen.getByRole('button', { name: new RegExp(`^${name}: `) })

const runFlow = () => screen.findByRole('region', { name: 'Run flow' })

describe('RunMap', () => {
  beforeEach(() => {
    get.mockReset()
  })

  it('draws the run as a flow: state, chunks, outputs and what flowed on', async () => {
    get.mockResolvedValue(data)
    renderMap()
    await runFlow()
    expect(get).toHaveBeenCalledWith('/api/v1/scan-runs/r1/map')
    expect(screen.getByText('Workflow version 2, as the run started')).toBeInTheDocument()
    // A chain is a list, in dependency order, each step joined to the last.
    const cards = screen.getAllByRole('button', { name: /Open the step$/ })
    expect(cards.map((c) => c.getAttribute('aria-label'))).toEqual([
      'Subdomains: Done. Open the step',
      'Probe: Waiting for a sensor. Open the step',
    ])
    expect(within(stepButton('Subdomains')).getByText('312 outputs')).toBeInTheDocument()
    expect(within(stepButton('Probe')).getByText('0/2 chunks')).toBeInTheDocument()
    expect(within(stepButton('Probe')).getByRole('progressbar')).toHaveAttribute(
      'aria-valuenow',
      '0'
    )
    expect(screen.getByText('312 outputs → Probe')).toBeInTheDocument()
    // No graph toggle for a chain.
    expect(screen.queryByRole('group', { name: 'View' })).not.toBeInTheDocument()
  })

  it('opens a step panel with its state, outputs and only its tasks', async () => {
    get.mockResolvedValue(data)
    renderMap()
    await runFlow()
    const select = (name: string) => fireEvent.click(stepButton(name))
    select('Probe')
    expect(stepButton('Probe')).toHaveAttribute('aria-pressed', 'true')
    const panel = await screen.findByRole('region', { name: 'Step Probe' })
    expect(within(panel).getAllByText('Waiting for a sensor').length).toBeGreaterThan(0)
    expect(within(panel).getByText('This step produced no assets.')).toBeInTheDocument()
    expect(within(panel).getAllByText('httpx').length).toBeGreaterThan(0)
    expect(within(panel).queryAllByText('subfinder')).toHaveLength(0)

    select('Probe') // the same step again closes it
    expect(screen.queryByRole('region', { name: 'Step Probe' })).not.toBeInTheDocument()

    // The keyboard opens a step too.
    stepButton('Subdomains').focus()
    await userEvent.keyboard('{Enter}')
    const sub = await screen.findByRole('region', { name: 'Step Subdomains' })
    expect(within(sub).getByText('domain')).toBeInTheDocument()
    expect(within(sub).getByText('312')).toBeInTheDocument()
  })

  it('refreshes when the run says it changed', async () => {
    get.mockResolvedValue(data)
    renderMap()
    await runFlow()
    const sub = channels[channels.length - 1]
    expect(sub.channelType).toBe('run')
    expect(sub.channelId).toBe('r1')
    const before = get.mock.calls.filter(([u]) => u === '/api/v1/scan-runs/r1/map').length
    await act(async () => sub.onData?.({ type: 'run.changed', run_id: 'r1' }))
    await waitFor(() =>
      expect(
        get.mock.calls.filter(([u]) => u === '/api/v1/scan-runs/r1/map').length
      ).toBeGreaterThan(before)
    )
  })

  it('compares with the previous run, previews outputs and warns about a step without output', async () => {
    const compared: RunMapData = {
      ...data,
      previous_run_id: 'r0',
      nodes: [
        {
          ...data.nodes![0],
          outputs: { total: 312, by_type: { domain: 312 }, previous: 300, added: 14, gone: 2 },
        },
        {
          step_key: 'ports',
          name: 'Ports',
          depends_on: ['subdomains'],
          state: 'succeeded',
          findings: 0,
          chunks: { total: 1, queued: 0, running: 0, completed: 1, failed: 0 },
          outputs: { total: 0, by_type: {}, previous: 40, added: 0, gone: 40 },
        },
      ],
    }
    get.mockImplementation((url: string) =>
      Promise.resolve(
        url.includes('/outputs?step_key=subdomains')
          ? {
              total: 312,
              previous_run_id: 'r0',
              outputs: [
                { asset_id: 'a1', name: 'new.acme.test', type: 'domain', new: true },
                { asset_id: 'a2', name: 'old.acme.test', type: 'domain', new: false },
              ],
            }
          : compared
      )
    )
    renderMap()
    await runFlow()
    expect(
      screen.getByText('Ports produced nothing, while the previous run produced 40.')
    ).toBeInTheDocument()
    expect(screen.getAllByText('+14 new, 2 gone').length).toBeGreaterThan(0)

    fireEvent.click(stepButton('Subdomains'))
    const panel = await screen.findByRole('region', { name: 'Step Subdomains' })
    const list = await within(panel).findByRole('list', { name: 'Outputs' })
    expect(get).toHaveBeenCalledWith('/api/v1/scan-runs/r1/outputs?step_key=subdomains&limit=20')
    expect(within(list).getByText('new.acme.test')).toBeInTheDocument()
    expect(within(list).getAllByText('New')).toHaveLength(1)
    expect(within(list).getByText('and 310 more')).toBeInTheDocument()
    expect(
      within(panel).getByText('Compared with the last run: +14 new, 2 gone')
    ).toBeInTheDocument()
  })

  it('says why a step was skipped and that a step could not reach its targets', async () => {
    // The live run of 2026-10-14: the port scan was refused by the
    // confined egress, the HTTP probe failed, the templates were skipped.
    const run: RunMapData = {
      run_id: 'r1',
      status: 'failed',
      nodes: [
        {
          step_key: 'ports',
          name: 'Port scan',
          tool: 'naabu',
          depends_on: [],
          state: 'succeeded',
          findings: 0,
          started_at: '2026-10-14T05:30:00Z',
          completed_at: '2026-10-14T05:30:48Z',
          chunks: { total: 2, queued: 0, running: 0, completed: 2, failed: 0 },
          outputs: { total: 0, by_type: {} },
        },
        {
          step_key: 'probe',
          name: 'HTTP probe',
          tool: 'httpx',
          depends_on: ['ports'],
          state: 'failed',
          reason: 'COMMAND_EXHAUSTED',
          findings: 0,
          chunks: { total: 1, queued: 0, running: 0, completed: 0, failed: 1 },
          outputs: { total: 0, by_type: {} },
        },
        {
          step_key: 'vulns',
          name: 'Vulnerability templates',
          depends_on: ['probe'],
          state: 'skipped',
          findings: 0,
          chunks: { total: 0, queued: 0, running: 0, completed: 0, failed: 0 },
          outputs: { total: 0, by_type: {} },
        },
      ],
      edges: [],
    }
    get.mockResolvedValue(run)
    render(
      <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
        <RunMap
          runId="r1"
          tasks={
            [
              { id: 'p1', step_key: 'ports', egress_refused_targets: 21 },
              { id: 'p2', step_key: 'ports', egress_refused_targets: 47 },
            ] as unknown as RunTask[]
          }
        />
      </SWRConfig>
    )
    await runFlow()
    const blocked =
      "Port scan could not reach 68 targets (blocked by the sensor's network confinement)."
    expect(within(screen.getByRole('status')).getByText(blocked)).toBeInTheDocument()
    expect(screen.queryByText('Port scan produced nothing.')).not.toBeInTheDocument()
    expect(within(stepButton('Port scan')).getByText(blocked)).toBeInTheDocument()
    expect(within(stepButton('Port scan')).getByText('Took 48s')).toBeInTheDocument()
    expect(
      within(stepButton('Vulnerability templates')).getByText('Skipped: HTTP probe failed')
    ).toBeInTheDocument()
    expect(within(stepButton('HTTP probe')).getByText('command exhausted')).toBeInTheDocument()
  })

  it("says on the step how many targets the sensor's target guard refused", async () => {
    const run: RunMapData = {
      run_id: 'r1',
      status: 'completed',
      nodes: [
        {
          step_key: 'probe',
          name: 'HTTP probe',
          tool: 'httpx',
          depends_on: [],
          state: 'succeeded',
          findings: 0,
          chunks: { total: 1, queued: 0, running: 0, completed: 1, failed: 0 },
          outputs: { total: 3, by_type: {} },
        },
      ],
      edges: [],
    }
    get.mockResolvedValue(run)
    render(
      <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
        <RunMap
          runId="r1"
          tasks={
            [{ id: 'p1', step_key: 'probe', guard_refused_targets: 2 }] as unknown as RunTask[]
          }
        />
      </SWRConfig>
    )
    await runFlow()
    const guarded = "HTTP probe: 2 targets refused by the sensor's target guard (not run)."
    expect(within(screen.getByRole('status')).getByText(guarded)).toBeInTheDocument()
    expect(within(stepButton('HTTP probe')).getByText(guarded)).toBeInTheDocument()
  })

  describe('with steps side by side', () => {
    const fan: RunMapData = {
      run_id: 'r1',
      status: 'running',
      nodes: [
        { ...data.nodes![0] },
        { ...data.nodes![1] },
        {
          step_key: 'ports',
          name: 'Ports',
          depends_on: ['subdomains'],
          state: 'running',
          started_at: '2026-10-14T05:30:00Z',
          findings: 0,
          chunks: { total: 4, queued: 1, running: 1, completed: 2, failed: 0 },
          outputs: { total: 0, by_type: {} },
        },
      ],
      edges: [
        { from: 'subdomains', to: 'probe', count: 312 },
        { from: 'subdomains', to: 'ports', count: 312 },
      ],
    }
    let width: PropertyDescriptor | undefined
    beforeEach(() => {
      width = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'clientWidth')
      Object.defineProperty(HTMLElement.prototype, 'clientWidth', {
        configurable: true,
        get: () => 1200,
      })
    })
    afterEach(() => {
      if (width) Object.defineProperty(HTMLElement.prototype, 'clientWidth', width)
    })

    it('draws a graph when it fits, with a list one click away', async () => {
      get.mockResolvedValue(fan)
      renderMap()
      await runFlow()
      const view = await screen.findByRole('group', { name: 'View' })
      const graph = within(view).getByRole('button', { name: 'Graph' })
      expect(graph).toHaveAttribute('aria-pressed', 'true')
      // The parallel steps share a layer, after the step they wait for.
      const layer = stepButton('Probe').closest('ul')!
      expect(within(layer).getByRole('button', { name: /^Ports: / })).toBeInTheDocument()
      expect(stepButton('Subdomains').closest('ul')).not.toBe(layer)

      fireEvent.click(within(view).getByRole('button', { name: 'List' }))
      expect(within(view).getByRole('button', { name: 'List' })).toHaveAttribute(
        'aria-pressed',
        'true'
      )
      // In the list, a step right after the one it waits for is joined to
      // it; one further down names what it waits for.
      expect(screen.getByText('312 outputs → Probe')).toBeInTheDocument()
      expect(screen.getByText('Waits for Subdomains')).toBeInTheDocument()
    })
  })

  it('says when the map cannot be loaded', async () => {
    get.mockRejectedValue(new Error('boom'))
    renderMap()
    await waitFor(() =>
      expect(screen.getByText('The run map could not be loaded.')).toBeInTheDocument()
    )
  })
})
