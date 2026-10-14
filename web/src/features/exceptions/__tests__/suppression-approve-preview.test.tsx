import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { SuppressionApprovePreview } from '../components/suppression-approve-preview'
import { useSuppressionPreview } from '../api/use-suppressions-api'

vi.mock('../api/use-suppressions-api', () => ({
  useSuppressionPreview: vi.fn(),
}))

type PreviewState = ReturnType<typeof useSuppressionPreview>
const mockPreview = (state: Partial<PreviewState>) =>
  vi.mocked(useSuppressionPreview).mockReturnValue(state as PreviewState)

describe('SuppressionApprovePreview', () => {
  beforeEach(() => vi.mocked(useSuppressionPreview).mockReset())

  it('fetches only for the rule passed in', () => {
    mockPreview({ isLoading: true })
    render(<SuppressionApprovePreview ruleId={undefined} />)
    expect(useSuppressionPreview).toHaveBeenCalledWith(undefined)
  })

  it('shows a loading state', () => {
    mockPreview({ isLoading: true })
    render(<SuppressionApprovePreview ruleId="r1" />)
    expect(screen.getByRole('status')).toHaveTextContent(/counting the open findings/i)
  })

  it('shows how many findings the approval closes', () => {
    mockPreview({ data: { matching_open_findings: 1234, capped: false, limit: 10000 } })
    render(<SuppressionApprovePreview ruleId="r1" />)
    expect(screen.getByText(/this will close 1\D?234 open findings/i)).toBeInTheDocument()
  })

  it('uses the singular for one finding', () => {
    mockPreview({ data: { matching_open_findings: 1, capped: false, limit: 10000 } })
    render(<SuppressionApprovePreview ruleId="r1" />)
    expect(screen.getByText('This will close 1 open finding.')).toBeInTheDocument()
  })

  it('says when nothing matches now', () => {
    mockPreview({ data: { matching_open_findings: 0, capped: false, limit: 10000 } })
    render(<SuppressionApprovePreview ruleId="r1" />)
    expect(screen.getByText(/no open findings match this rule now/i)).toBeInTheDocument()
  })

  it('says when the count is capped', () => {
    mockPreview({ data: { matching_open_findings: 10000, capped: true, limit: 10000 } })
    render(<SuppressionApprovePreview ruleId="r1" />)
    expect(screen.getByText(/more than 10\D?000 open findings match/i)).toBeInTheDocument()
  })

  it('shows an error state', () => {
    mockPreview({ error: new Error('boom') })
    render(<SuppressionApprovePreview ruleId="r1" />)
    expect(screen.getByText(/could not count the open findings/i)).toBeInTheDocument()
  })
})
