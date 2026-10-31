/**
 * The inline monitoring control: with assets:write the row's state opens a
 * menu of ownership decisions (every one but the decision in force, each with
 * what it does), and a pick is one PUT of the typed attribution command, then
 * the list refreshes. Without assets:write it is the plain chip.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

const { MonitoringStateControl, monitoringDecisions } = await import('../monitoring-state-control')

beforeEach(() => {
  api.put.mockReset().mockResolvedValue({ state: 'rejected', confidence: 100, evidence: [] })
})

describe('MonitoringStateControl', () => {
  it('records the picked decision with one PUT and refreshes the list', async () => {
    const onChanged = vi.fn()
    render(
      <MonitoringStateControl
        assetId="a1"
        assetName="dev.example.com"
        state="pending_decision"
        attributionState="needs_review"
        canWrite
        onChanged={onChanged}
      />
    )
    await userEvent.click(
      screen.getByRole('button', { name: 'Pending decision, change monitoring of dev.example.com' })
    )
    expect(await screen.findByText('Decide monitoring')).toBeInTheDocument()
    // What each choice does is written next to it.
    expect(screen.getByText(/It is not yours\./)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('menuitem', { name: /Not ours/ }))
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/v1/assets/a1/attribution', { state: 'rejected' })
    )
    expect(api.put).toHaveBeenCalledTimes(1)
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
  })

  it('is the plain state chip without assets:write', () => {
    render(<MonitoringStateControl assetId="a1" assetName="x" state="monitored" canWrite={false} />)
    expect(screen.queryByRole('button')).toBeNull()
    expect(screen.getByText('Monitored')).toBeInTheDocument()
  })
})

describe('monitoringDecisions', () => {
  it('offers every decision but the one in force, and a way back to review once decided', () => {
    expect(monitoringDecisions('needs_review')).toEqual([
      'confirmed',
      'monitor_only',
      'dependency',
      'rejected',
    ])
    expect(monitoringDecisions('confirmed')).toEqual([
      'monitor_only',
      'dependency',
      'rejected',
      'needs_review',
    ])
  })
})
