import { act, render, screen, waitFor, within } from '@testing-library/react'
import { SWRConfig } from 'swr'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { RunMap as RunMapData, RunTask } from '@/lib/api/generated'

const get = vi.fn()
vi.mock('@/lib/api/client', () => ({ get: (url: string) => get(url) }))

// The shared component is tested on its own; here only what the run map
// hands it matters.
const seen: Record<string, unknown>[] = []
vi.mock('@/features/scan-workflows/components/workflow-stages', () => ({
  WorkflowStagesView: (props: Record<string, unknown>) => {
    seen.push(props)
    const badge = props.badge as Record<string, React.ReactNode>
    return <div data-testid="stages">{Object.values(badge)}</div>
  },
}))

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

describe('RunMap', () => {
  beforeEach(() => {
    get.mockReset()
    seen.length = 0
  })

  it('draws the run map on the shared stages component', async () => {
    get.mockResolvedValue(data)
    renderMap()
    await screen.findByTestId('stages')
    expect(get).toHaveBeenCalledWith('/api/v1/scan-runs/r1/map')
    expect(screen.getByText('Workflow version 2, as the run started')).toBeInTheDocument()
    expect(screen.getByText('312 outputs')).toBeInTheDocument()
    expect(screen.getByText('Waiting for a sensor')).toBeInTheDocument()

    const props = seen[seen.length - 1]
    expect((props.steps as { step_key: string }[]).map((s) => s.step_key)).toEqual([
      'subdomains',
      'probe',
    ])
    expect(props.status).toEqual({ subdomains: 'completed', probe: 'pending' })
    const edgeLabel = props.edgeLabel as (a: string, b: string) => string | undefined
    expect(edgeLabel('subdomains', 'probe')).toBe('312')
  })

  it('opens a step panel with its state, outputs and only its tasks', async () => {
    get.mockResolvedValue(data)
    renderMap()
    await screen.findByTestId('stages')
    const select = seen[seen.length - 1].onSelectStep as (key: string) => void
    act(() => select('probe'))
    const panel = await screen.findByRole('region', { name: 'Step Probe' })
    expect(within(panel).getAllByText('Waiting for a sensor').length).toBeGreaterThan(0)
    expect(within(panel).getByText('Nothing produced yet.')).toBeInTheDocument()
    expect(within(panel).getAllByText('httpx').length).toBeGreaterThan(0)
    expect(within(panel).queryAllByText('subfinder')).toHaveLength(0)

    act(() => select('probe')) // the same step again closes it
    expect(screen.queryByRole('region', { name: 'Step Probe' })).not.toBeInTheDocument()

    act(() => select('subdomains'))
    const sub = await screen.findByRole('region', { name: 'Step Subdomains' })
    expect(within(sub).getByText('domain')).toBeInTheDocument()
    expect(within(sub).getByText('312')).toBeInTheDocument()
  })

  it('refreshes when the run says it changed', async () => {
    get.mockResolvedValue(data)
    renderMap()
    await screen.findByTestId('stages')
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
    await screen.findByTestId('stages')
    expect(
      screen.getByText('Ports produced nothing, while the previous run produced 40.')
    ).toBeInTheDocument()
    expect(screen.getAllByText('+14 new, 2 gone').length).toBeGreaterThan(0)

    const select = seen[seen.length - 1].onSelectStep as (key: string) => void
    act(() => select('subdomains'))
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

  it('says when the map cannot be loaded', async () => {
    get.mockRejectedValue(new Error('boom'))
    renderMap()
    await waitFor(() =>
      expect(screen.getByText('The run map could not be loaded.')).toBeInTheDocument()
    )
  })
})
