import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'

import { get } from '@/lib/api/client'
import { FeedDataAsOf, FeedFreshnessBanner } from '../feed-freshness-banner'

vi.mock('@/lib/api/client', () => ({ get: vi.fn() }))

function renderIt(node: React.ReactNode) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{node}</SWRConfig>
  )
}

const threeDaysAgo = () => new Date(Date.now() - 3 * 24 * 3600 * 1000).toISOString()

describe('FeedFreshnessBanner', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows nothing while the data is current', async () => {
    vi.mocked(get).mockResolvedValue({ stale: false, reasons: [], data_as_of: threeDaysAgo() })
    const { container } = renderIt(<FeedFreshnessBanner />)
    await waitFor(() => expect(get).toHaveBeenCalledWith('/api/v1/threat-intel/freshness'))
    expect(container).toBeEmptyDOMElement()
  })

  it('tells every user the data is old, with no way to dismiss it', async () => {
    vi.mocked(get).mockResolvedValue({
      stale: true,
      reasons: ['data_stale'],
      stale_since: threeDaysAgo(),
    })
    renderIt(<FeedFreshnessBanner />)
    const banner = await screen.findByRole('alert')
    expect(banner).toHaveTextContent('Vulnerability data is out of date')
    expect(banner).toHaveTextContent('3 days ago')
    expect(banner).toHaveTextContent('New vulnerabilities may not be shown')
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('says the data was never loaded when there is no date', async () => {
    vi.mocked(get).mockResolvedValue({ stale: true, reasons: ['data_stale'] })
    renderIt(<FeedFreshnessBanner />)
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Vulnerability data has not been loaded yet.'
    )
  })

  it('says the check is not running when that is the only reason', async () => {
    vi.mocked(get).mockResolvedValue({ stale: true, reasons: ['check_not_running'] })
    renderIt(<FeedFreshnessBanner />)
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'has not been able to check its vulnerability data recently'
    )
  })

  it('stays quiet when the freshness cannot be read', async () => {
    vi.mocked(get).mockRejectedValue(new Error('network'))
    const { container } = renderIt(<FeedFreshnessBanner />)
    await waitFor(() => expect(get).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
  })
})

describe('FeedDataAsOf', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows when the data was published, and marks it out of date when stale', async () => {
    vi.mocked(get).mockResolvedValue({
      stale: true,
      reasons: ['data_stale'],
      data_as_of: '2026-11-15T12:00:00Z',
    })
    renderIt(<FeedDataAsOf />)
    const line = await screen.findByTestId('feed-data-as-of')
    expect(line).toHaveTextContent(/Data as of .*2026.*\(out of date\)/)
  })

  it('shows nothing without a date', async () => {
    vi.mocked(get).mockResolvedValue({ stale: false, reasons: [] })
    const { container } = renderIt(<FeedDataAsOf />)
    await waitFor(() => expect(get).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
  })
})
