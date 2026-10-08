import { render, screen, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { RunMap as RunMapData } from '@/lib/api/generated'

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

const renderMap = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <RunMap runId="r1" />
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

  it('says when the map cannot be loaded', async () => {
    get.mockRejectedValue(new Error('boom'))
    renderMap()
    await waitFor(() =>
      expect(screen.getByText('The run map could not be loaded.')).toBeInTheDocument()
    )
  })
})
