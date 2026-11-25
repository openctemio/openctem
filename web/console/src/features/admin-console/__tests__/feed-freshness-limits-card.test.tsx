import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { saveFeedFreshnessLimits, useFeedFreshnessLimits } from '../api/use-platform-settings'
import { FeedFreshnessLimitsCard, epssHoursFor } from '../components/feed-freshness-limits-card'
import type { FeedFreshnessLimits } from '../types'

vi.mock('../api/use-platform-settings', async (orig) => ({
  ...(await orig<typeof import('../api/use-platform-settings')>()),
  useFeedFreshnessLimits: vi.fn(),
  saveFeedFreshnessLimits: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const base: FeedFreshnessLimits = {
  bundle_hours: 12,
  epss_hours: 36,
  source: 'default',
  default_hours: 12,
  min_hours: 6,
  max_hours: 168,
  version: 0,
}

function mockData(d: FeedFreshnessLimits) {
  vi.mocked(useFeedFreshnessLimits).mockReturnValue({
    data: d,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  } as unknown as ReturnType<typeof useFeedFreshnessLimits>)
}

describe('FeedFreshnessLimitsCard', () => {
  beforeEach(() => vi.clearAllMocks())

  it('EPSS follows the bundle limit with a day more, never under 36 hours', () => {
    expect(epssHoursFor(6)).toBe(36)
    expect(epssHoursFor(12)).toBe(36)
    expect(epssHoursFor(48)).toBe(72)
  })

  it('an offline site raises the limit; EPSS follows and the save sends the version read', async () => {
    mockData(base)
    vi.mocked(saveFeedFreshnessLimits).mockResolvedValue({ ...base, bundle_hours: 48, version: 1 })
    render(<FeedFreshnessLimitsCard canEdit />)
    const input = screen.getByLabelText('Vulnerability bundles and CISA KEV, in hours')
    await userEvent.clear(input)
    await userEvent.type(input, '48')
    expect(
      screen.getByText('EPSS scores are dated by day: their limit is 72 hours.')
    ).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /save/i }))
    expect(saveFeedFreshnessLimits).toHaveBeenCalledWith({ bundle_hours: 48, version: 0 })
  })

  it('refuses a value outside the bounds and does not offer to save it', async () => {
    mockData(base)
    render(<FeedFreshnessLimitsCard canEdit />)
    const input = screen.getByLabelText('Vulnerability bundles and CISA KEV, in hours')
    await userEvent.clear(input)
    await userEvent.type(input, '200')
    expect(screen.getByText('A whole number from 6 to 168.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /save/i })).toBeNull()
  })

  it('is read only without the permission', () => {
    mockData({ ...base, source: 'console', bundle_hours: 24, epss_hours: 48, version: 2 })
    render(<FeedFreshnessLimitsCard canEdit={false} />)
    expect(screen.getByLabelText('Vulnerability bundles and CISA KEV, in hours')).toBeDisabled()
    expect(screen.getByText('Set in this console. The default is 12 hours.')).toBeInTheDocument()
  })
})
