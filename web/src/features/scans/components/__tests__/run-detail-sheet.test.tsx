import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SWRConfig } from 'swr'

// The body GET /scan-runs/{id} really sends: written by the API's
// TestRunResponse_WebFixture from the handler's own response.
import apiRun from './fixtures/scan-run.api.json'
import { RunDetailSheet } from '../run-detail-sheet'

const getMock = vi.fn()
vi.mock('@/lib/api/client', () => ({ get: (url: string) => getMock(url) }))

// The sheet's own reads are under test; its sections are stubs.
vi.mock('next/dynamic', () => ({
  default: () =>
    function RunMapStub({ runId }: { runId: string }) {
      return <div data-testid="run-map">{runId}</div>
    },
}))
vi.mock('../run-stage-lanes', () => ({ RunStageLanes: () => null }))
vi.mock('../run-timeline', () => ({ RunTimeline: () => null }))
vi.mock('../run-tasks-table', () => ({ RunTasksTable: () => null }))

const renderSheet = (runId: string) =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <RunDetailSheet runId={runId} onOpenChange={() => {}} />
    </SWRConfig>
  )

describe('RunDetailSheet on the real run response', () => {
  beforeEach(() => getMock.mockReset())

  it('draws the run map for a run the API returns with step runs', async () => {
    expect(apiRun.scan_run_steps.length).toBeGreaterThan(0)
    getMock.mockResolvedValue(apiRun)
    renderSheet(apiRun.id)

    expect(await screen.findByTestId('run-map')).toHaveTextContent(apiRun.id)
    expect(screen.getByText('Run map')).toBeInTheDocument()
    expect(getMock).toHaveBeenCalledWith(`/api/v1/scan-runs/${apiRun.id}`)
  })

  it('leaves the run map out for a run without step runs', async () => {
    const { scan_run_steps: _steps, ...withoutSteps } = apiRun
    getMock.mockResolvedValue(withoutSteps)
    renderSheet(apiRun.id)

    expect(await screen.findByText('Timeline')).toBeInTheDocument()
    expect(screen.queryByTestId('run-map')).not.toBeInTheDocument()
  })
})
