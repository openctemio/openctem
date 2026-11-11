import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ComplianceBenchmark } from '../../api/compliance-checks-api'

const api = vi.hoisted(() => ({
  benchmarks: vi.fn(),
  controls: vi.fn(),
  assets: vi.fn(),
}))

vi.mock('../../api/compliance-checks-api', () => ({
  useComplianceBenchmarks: () => api.benchmarks(),
  useComplianceControls: (key: string | undefined, opts: unknown) => api.controls(key, opts),
  useComplianceControlAssets: (key: string | undefined, control: string | undefined) =>
    api.assets(key, control),
}))

import { ComplianceBenchmarksPanel } from '../compliance-benchmarks-panel'

const counts = (pass: number, fail: number) => ({
  pass,
  fail,
  manual: 0,
  not_applicable: 2,
  error: 1,
  excepted: 0,
  applicable: pass + fail,
})

const bench: ComplianceBenchmark = {
  key: 'cis-example-linux',
  name: 'CIS Example Linux',
  version: '1.0.0',
  framework: 'cis',
  assets: 4,
  failing_assets: 3,
  counts: counts(30, 10),
  pass_rate: 0.75,
  last_checked_at: '2026-11-01T00:00:00Z',
}

describe('ComplianceBenchmarksPanel', () => {
  beforeEach(() => {
    api.benchmarks.mockReset()
    api.controls.mockReset()
    api.assets.mockReset()
    api.controls.mockReturnValue({ data: undefined, isLoading: false })
    api.assets.mockReturnValue({ data: undefined, isLoading: false })
  })

  it('lists each benchmark with its pass rate and failing assets', () => {
    api.benchmarks.mockReturnValue({ data: { data: [bench] }, isLoading: false })
    render(<ComplianceBenchmarksPanel />)
    const row = screen.getByTestId('compliance-benchmark-cis-example-linux')
    expect(within(row).getByText('CIS Example Linux v1.0.0')).toBeInTheDocument()
    expect(within(row).getByText('75%')).toBeInTheDocument()
    expect(within(row).getByRole('meter')).toHaveAttribute('aria-valuenow', '75')
    expect(within(row).getByText('3 of 4')).toBeInTheDocument()
  })

  it('says how to get checks when there are none', () => {
    api.benchmarks.mockReturnValue({ data: { data: [] }, isLoading: false })
    render(<ComplianceBenchmarksPanel />)
    expect(screen.getByTestId('compliance-benchmarks-empty')).toBeInTheDocument()
  })

  it('opens a benchmark on its failing controls, then a control on its assets', async () => {
    api.benchmarks.mockReturnValue({ data: { data: [bench] }, isLoading: false })
    api.controls.mockReturnValue({
      data: {
        data: [
          {
            control_id: '1.1',
            control_name: 'Ensure x',
            level: 1,
            counts: counts(1, 3),
            pass_rate: 0.25,
            last_checked_at: '2026-11-01T00:00:00Z',
          },
        ],
        total: 1,
        page: 1,
        per_page: 50,
        total_pages: 1,
      },
      isLoading: false,
    })
    api.assets.mockReturnValue({
      data: {
        data: [
          {
            asset_id: 'a1',
            asset_name: 'h1.example.com',
            asset_type: 'host',
            result: 'fail',
            evidence: { actual: '0', expected: '1' },
            finding_id: 'f1',
            last_checked_at: '2026-11-01T00:00:00Z',
            last_changed_at: '2026-11-01T00:00:00Z',
          },
        ],
        total: 1,
        page: 1,
        per_page: 100,
        total_pages: 1,
      },
      isLoading: false,
    })
    render(<ComplianceBenchmarksPanel />)
    await userEvent.click(screen.getByRole('button', { name: 'CIS Example Linux v1.0.0' }))
    expect(api.controls).toHaveBeenLastCalledWith(
      'cis-example-linux',
      expect.objectContaining({ failedOnly: true })
    )
    const control = await screen.findByTestId('compliance-control-1.1')
    await userEvent.click(within(control).getByRole('button', { expanded: false }))
    const assets = await screen.findByTestId('compliance-control-assets-1.1')
    expect(within(assets).getByText('h1.example.com')).toBeInTheDocument()
    expect(within(assets).getByRole('link', { name: 'Open finding' })).toHaveAttribute(
      'href',
      '/findings/f1'
    )
    // Every control, not only the failing ones.
    await userEvent.click(screen.getByRole('switch'))
    expect(api.controls).toHaveBeenLastCalledWith(
      'cis-example-linux',
      expect.objectContaining({ failedOnly: false })
    )
  })
})
