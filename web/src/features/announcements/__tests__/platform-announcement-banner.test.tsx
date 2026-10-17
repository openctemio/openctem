import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'

import { get } from '@/lib/api/client'
import { PlatformAnnouncementBanner } from '../components/platform-announcement-banner'

vi.mock('@/lib/api/client', () => ({ get: vi.fn() }))

function renderBanner() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <PlatformAnnouncementBanner />
    </SWRConfig>
  )
}

describe('PlatformAnnouncementBanner', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.localStorage.clear()
  })

  it('shows nothing without an active announcement', async () => {
    vi.mocked(get).mockResolvedValue({ data: [] })
    const { container } = renderBanner()
    await waitFor(() => expect(get).toHaveBeenCalledWith('/api/v1/announcements'))
    expect(container).toBeEmptyDOMElement()
  })

  it('renders the message as text, never HTML, and remembers a dismissal', async () => {
    const user = userEvent.setup()
    vi.mocked(get).mockResolvedValue({
      data: [
        {
          id: 'a1',
          message: 'Maintenance at 22:00 <img src=x onerror=alert(1)>',
          severity: 'maintenance',
          starts_at: '2026-10-08T10:00:00Z',
        },
      ],
    })
    const { container } = renderBanner()
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Maintenance at 22:00 <img src=x onerror=alert(1)>'
    )
    expect(container.querySelector('img')).toBeNull()

    await user.click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(screen.queryByRole('alert')).toBeNull()
    expect(JSON.parse(window.localStorage.getItem('openctem.dismissedAnnouncements')!)).toEqual([
      'a1',
    ])
  })
})
