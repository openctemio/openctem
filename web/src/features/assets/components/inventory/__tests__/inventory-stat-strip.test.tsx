/**
 * The inventory strip's "Internet-facing" counts and filters internet_facing
 * (the one definition: exposure public or reported reachable), and a failed
 * stats request shows "—", never 0.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { InventoryStatStrip } from '../inventory-stat-strip'
import type { AssetStatsData } from '../../../hooks/use-assets'

const stats = {
  total: 36,
  byCriticality: { critical: 2 },
  byExposure: { public: 20 },
  byInternetFacing: { true: 28, false: 8 },
  byHasOwner: { true: 30, false: 6 },
  withFindings: 5,
  highRiskCount: 3,
  metadataCounts: {},
} as unknown as AssetStatsData

describe('InventoryStatStrip', () => {
  it('counts and toggles internet-facing, not exposure alone', async () => {
    const onChange = vi.fn()
    render(<InventoryStatStrip stats={stats} filters={{}} onChange={onChange} />)
    const metric = screen.getByRole('button', { name: /Internet-facing/i })
    expect(metric).toHaveTextContent('28')
    await userEvent.click(metric)
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ isInternetFacing: true }))
    expect(onChange.mock.calls[0][0].exposures).toBeUndefined()
  })

  it('shows a dash instead of zeros when the counts failed', () => {
    render(<InventoryStatStrip stats={stats} filters={{}} onChange={vi.fn()} isError />)
    expect(screen.getAllByText('—').length).toBeGreaterThan(3)
    expect(screen.queryByText('28')).toBeNull()
  })
})
