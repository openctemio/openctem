import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { SWRConfig } from 'swr'

import { TooltipProvider } from '@/components/ui/tooltip'
import {
  RunStageLanes,
  chunkSummary,
  skipLabel,
  skippedReasons,
  stageLabel,
} from '../run-stage-lanes'

const getMock = vi.fn()
// Labels come from the served capability catalog (GET /scans/stages).
const CATALOG = {
  stages: [
    { key: 'discover.subdomains', name: 'Subdomain discovery', implementations: [] },
    { key: 'scan.ports', name: 'Port scan', implementations: [] },
  ],
}
vi.mock('@/lib/api/client', () => ({
  get: (url: string) => (url === '/api/v1/scans/stages' ? Promise.resolve(CATALOG) : getMock(url)),
}))

const fresh = (ui: React.ReactNode) =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <TooltipProvider>{ui}</TooltipProvider>
    </SWRConfig>
  )

describe('RunStageLanes', () => {
  beforeEach(() => getMock.mockReset())

  it('shows each stage with its tier and the counts the API returns', async () => {
    getMock.mockResolvedValue({
      data: [
        {
          stage_key: 'subs',
          stage: 'discover.subdomains',
          tool: 'subfinder',
          tier: 'T0',
          chained: false,
          inputs: 1,
          planned: 1,
          skipped: {},
          max_hop: 0,
        },
        {
          stage_key: 'ports',
          stage: 'scan.ports',
          tool: 'naabu',
          tier: 'T1',
          chained: true,
          inputs: 7,
          planned: 3,
          skipped: { unconfirmed: 2, excluded: 1, over_cap: 1 },
          max_hop: 2,
        },
      ],
    })
    fresh(<RunStageLanes runId="run-1" />)
    const lanes = await screen.findAllByTestId('stage-lane')
    expect(getMock).toHaveBeenCalledWith('/api/v1/scan-runs/run-1/stages')
    expect(lanes).toHaveLength(2)
    expect(within(lanes[0]).getByText('Subdomain discovery')).toBeInTheDocument()
    expect(within(lanes[0]).getByText(/T0/)).toBeInTheDocument()
    const ports = lanes[1]
    expect(within(ports).getByText('Port scan')).toBeInTheDocument()
    expect(within(ports).getByText('chained')).toBeInTheDocument()
    expect(within(ports).getByText(/up to 2 hop/)).toBeInTheDocument()
    // Counts are rendered as given, not recomputed from the reasons.
    expect(ports.textContent).toContain('In 7')
    expect(ports.textContent).toContain('planned 3')
    const reasons = within(ports).getByRole('list', { name: 'Skipped targets by reason' })
    const items = within(reasons).getAllByRole('listitem')
    expect(items[0].textContent).toContain('2')
    expect(items[0].textContent).toContain('ownership not confirmed')
    expect(items).toHaveLength(3)
  })

  it('renders a tenant-authored step key through TruncatedText', async () => {
    const long = 'step-' + 'x'.repeat(300) + '‮'
    getMock.mockResolvedValue({
      data: [
        {
          stage_key: long,
          stage: '',
          tool: 'custom',
          tier: 'T1',
          inputs: 0,
          planned: 0,
          skipped: {},
        },
      ],
    })
    fresh(<RunStageLanes runId="r" />)
    const lane = await screen.findByTestId('stage-lane')
    expect(within(lane).getByText('Custom step')).toBeInTheDocument()
    const truncated = lane.querySelectorAll('[data-slot="truncated-text"]')
    expect(truncated.length).toBeGreaterThan(0)
    for (const el of truncated) expect(el.textContent).not.toContain('‮')
  })

  it('says when nothing was planned and when the stages cannot be loaded', async () => {
    getMock.mockResolvedValueOnce({ data: [] })
    const { unmount } = fresh(<RunStageLanes runId="r" />)
    expect(await screen.findByText(/No stage of this run has been planned yet/)).toBeInTheDocument()
    unmount()
    getMock.mockRejectedValueOnce(new Error('boom'))
    fresh(<RunStageLanes runId="r2" />)
    expect(await screen.findByText(/Could not load the stages/)).toBeInTheDocument()
  })
})

describe('RunStageLanes chunks', () => {
  beforeEach(() => getMock.mockReset())

  it('shows chunk counts and the sensors that took them, as the API gives them', async () => {
    getMock.mockResolvedValue({
      data: [
        {
          stage_key: 'http',
          stage: 'probe.http',
          tool: 'httpx',
          tier: 'T1',
          inputs: 450,
          planned: 450,
          skipped: {},
          chunks: { total: 3, queued: 1, running: 1, completed: 1, failed: 0 },
          sensors: [
            { sensor_id: 's1', sensor_name: 'edge-1', total: 1, completed: 1 },
            { platform: true, total: 1, running: 1 },
          ],
        },
      ],
    })
    fresh(<RunStageLanes runId="run-c" />)
    const chunks = await screen.findByTestId('stage-chunks')
    expect(chunks.textContent).toContain('1 of 3 chunks done, 1 running, 1 queued')
    const bySensor = within(chunks).getByRole('list', { name: 'Chunks by sensor' })
    const rows = within(bySensor).getAllByRole('listitem')
    expect(rows).toHaveLength(2)
    expect(rows[0].textContent).toContain('edge-1')
    expect(rows[0].textContent).toContain('1 chunk(s), 1 done')
    expect(rows[1].textContent).toContain('Platform scanning')
  })
})

describe('stage lane helpers', () => {
  it('summarizes chunks only for a chunked stage', () => {
    expect(chunkSummary(undefined)).toBe('')
    expect(chunkSummary({ total: 1, completed: 1 })).toBe('')
    expect(chunkSummary({ total: 4, completed: 2, failed: 2 })).toBe('2 of 4 chunks done, 2 failed')
  })

  it('labels stages and skip reasons, with fallbacks', () => {
    expect(stageLabel('probe.http', { 'probe.http': 'HTTP probe' })).toBe('HTTP probe')
    expect(stageLabel('probe.http')).toBe('probe.http')
    expect(stageLabel('future.stage')).toBe('future.stage')
    expect(stageLabel(undefined)).toBe('Custom step')
    expect(skipLabel('hop_limit')).toBe('too many hops from the seeds')
    expect(skipLabel('new_reason')).toBe('new reason')
  })

  it('orders reasons by count and drops zeros', () => {
    expect(skippedReasons({ a: 1, b: 3, c: 0 })).toEqual([
      ['b', 3],
      ['a', 1],
    ])
    expect(skippedReasons(undefined)).toEqual([])
  })
})
