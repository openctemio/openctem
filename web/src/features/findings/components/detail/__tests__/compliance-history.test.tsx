import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const history = vi.hoisted(() => vi.fn())
vi.mock('../../../api/compliance-checks-api', () => ({
  useFindingComplianceHistory: (id: string) => history(id),
}))

import { ComplianceHistory } from '../compliance-history'

describe('ComplianceHistory', () => {
  it('lists every change of the control, newest first, with the previous result', () => {
    history.mockReturnValue({
      data: {
        control: {
          benchmark_key: 'cis-x',
          benchmark_name: 'CIS X',
          control_id: '1.1',
          result: 'pass',
          last_checked_at: '2026-11-02T00:00:00Z',
        },
        data: [
          {
            result: 'pass',
            previous_result: 'fail',
            evidence: { actual: '1' },
            source: 'ingest',
            observed_at: '2026-11-02T00:00:00Z',
            recorded_at: '2026-11-02T00:00:00Z',
          },
          {
            result: 'fail',
            evidence: { actual: '0' },
            source: 'backfill',
            observed_at: '2026-11-01T00:00:00Z',
            recorded_at: '2026-11-01T00:00:00Z',
          },
        ],
      },
      isLoading: false,
    })
    render(<ComplianceHistory findingId="f1" />)
    expect(history).toHaveBeenCalledWith('f1')
    expect(screen.getByText('Status history (2)')).toBeInTheDocument()
    expect(screen.getByText('was Failed')).toBeInTheDocument()
    expect(screen.getByText('from the stored finding')).toBeInTheDocument()
    expect(screen.getAllByTestId('compliance-history')).toHaveLength(1)
  })

  it('shows nothing for a finding without a check state', () => {
    history.mockReturnValue({ data: { control: null, data: [] }, isLoading: false })
    const { container } = render(<ComplianceHistory findingId="f2" />)
    expect(container).toBeEmptyDOMElement()
  })
})
