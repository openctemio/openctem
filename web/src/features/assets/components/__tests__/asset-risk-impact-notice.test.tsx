/**
 * Lowering exposure or criticality in the asset edit dialog: nothing shows for
 * unchanged or raised values; a lowering shows the API's preview, the
 * approval it needs and the reason field when an open P0/P1 would drop.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { AssetRiskImpactNotice, type RiskNoticeState } from '../asset-risk-impact-notice'
import type { Asset } from '../../types'

const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), del: vi.fn(), post: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

const asset = { id: 'a1', criticality: 'high', exposure: 'public' } as unknown as Asset

const preview = (over: Record<string, unknown> = {}, approval?: Record<string, unknown>) => ({
  impact: {
    lowered_fields: ['exposure'],
    open_findings: 4,
    class_drops: 2,
    p0_p1_drops: 1,
    raised: 0,
    moves: [{ from: 'P1', to: 'P2', count: 2 }],
    manual_overrides_kept: 0,
    ...over,
  },
  approval,
  pending_request: false,
})

function Host(props: {
  criticality: string
  exposure: string
  onState: (s: RiskNoticeState) => void
}) {
  const [reason, setReason] = useState('')
  return (
    <AssetRiskImpactNotice
      asset={asset}
      criticality={props.criticality}
      exposure={props.exposure}
      reason={reason}
      onReasonChange={setReason}
      onStateChange={props.onState}
    />
  )
}

beforeEach(() => api.post.mockReset())

describe('AssetRiskImpactNotice', () => {
  it('shows nothing and asks nothing when risk is unchanged or raised', async () => {
    const onState = vi.fn()
    const { container, rerender } = render(
      <Host criticality="high" exposure="public" onState={onState} />
    )
    rerender(<Host criticality="critical" exposure="public" onState={onState} />)
    expect(container).toBeEmptyDOMElement()
    expect(api.post).not.toHaveBeenCalled()
  })

  it('previews a lowering and asks for a second person and a reason when a P0/P1 would drop', async () => {
    api.post.mockResolvedValue(
      preview(
        {},
        {
          required: true,
          tier: 'peer',
          required_approvals: 1,
          reasons: [],
          eligible_approvers: 2,
          satisfiable: true,
          min_note_length: 1,
          step_up: false,
        }
      )
    )
    const onState = vi.fn()
    render(<Host criticality="high" exposure="isolated" onState={onState} />)

    expect(await screen.findByTestId('risk-impact-needs-approval')).toBeInTheDocument()
    expect(api.post).toHaveBeenCalledWith('/api/v1/assets/a1/risk-impact', { exposure: 'isolated' })
    expect(screen.getByTestId('risk-impact-moves')).toHaveTextContent('P1 to P2: 2')
    expect(screen.getByText(/2 of 4 open findings/)).toBeInTheDocument()
    await waitFor(() =>
      expect(onState).toHaveBeenLastCalledWith({ needsReason: true, blocked: false })
    )

    await userEvent.type(
      screen.getByLabelText('Reason for lowering the risk'),
      'behind the gateway'
    )
    expect(screen.getByLabelText('Reason for lowering the risk')).toHaveValue('behind the gateway')
  })

  it('says so when nobody can approve, and blocks', async () => {
    api.post.mockResolvedValue(
      preview(
        {},
        {
          required: true,
          tier: 'peer',
          required_approvals: 1,
          reasons: [],
          eligible_approvers: 0,
          satisfiable: false,
          min_note_length: 1,
          step_up: false,
        }
      )
    )
    const onState = vi.fn()
    render(<Host criticality="high" exposure="isolated" onState={onState} />)
    expect(await screen.findByTestId('risk-impact-no-approver')).toBeInTheDocument()
    await waitFor(() =>
      expect(onState).toHaveBeenLastCalledWith({ needsReason: true, blocked: true })
    )
  })

  it('needs no reason and no approval when no open P0/P1 would drop', async () => {
    api.post.mockResolvedValue(preview({ p0_p1_drops: 0, class_drops: 0, moves: [] }))
    const onState = vi.fn()
    render(<Host criticality="low" exposure="public" onState={onState} />)
    expect(await screen.findByText(/No open finding on this asset would move/)).toBeInTheDocument()
    expect(screen.queryByLabelText('Reason for lowering the risk')).not.toBeInTheDocument()
    expect(screen.queryByTestId('risk-impact-needs-approval')).not.toBeInTheDocument()
    expect(onState).toHaveBeenLastCalledWith({ needsReason: false, blocked: false })
  })

  it('tells a person who may decide alone, and shows a failed preview', async () => {
    api.post.mockResolvedValueOnce(
      preview(
        {},
        {
          required: false,
          tier: 'single',
          required_approvals: 0,
          reasons: [],
          eligible_approvers: 2,
          satisfiable: true,
          min_note_length: 1,
          step_up: false,
        }
      )
    )
    const { unmount } = render(<Host criticality="high" exposure="isolated" onState={vi.fn()} />)
    expect(await screen.findByTestId('risk-impact-alone')).toBeInTheDocument()
    unmount()

    api.post.mockRejectedValueOnce(new Error('boom'))
    render(<Host criticality="high" exposure="isolated" onState={vi.fn()} />)
    expect(await screen.findByTestId('risk-impact-error')).toBeInTheDocument()
  })
})
