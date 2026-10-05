import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'

import { SchedulePreview } from '../schedule-preview'

const postMock = vi.fn()
vi.mock('@/lib/api/client', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api/client')>()),
  post: (...a: unknown[]) => postMock(...a),
}))
let tenant: { id: string } | null = { id: 'tenant-a' }
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: tenant }),
}))

function renderFresh(ui: React.ReactElement) {
  return render(<SWRConfig value={{ provider: () => new Map() }}>{ui}</SWRConfig>)
}

describe('SchedulePreview', () => {
  beforeEach(() => {
    postMock.mockReset()
    tenant = { id: 'tenant-a' }
  })

  it('lists the occurrences the API computed, in the scan timezone', async () => {
    postMock.mockResolvedValue({
      timezone: 'Asia/Tokyo',
      occurrences: ['2099-10-12T02:30:00+09:00', '2099-10-19T02:30:00+09:00'],
    })
    renderFresh(
      <SchedulePreview
        request={{
          schedule_type: 'weekly',
          schedule_day: 1,
          schedule_time: '02:30',
          timezone: 'Asia/Tokyo',
          count: 2,
        }}
      />
    )
    const items = await screen.findAllByRole('listitem')
    expect(items).toHaveLength(2)
    expect(items[0]).toHaveTextContent('02:30')
    expect(screen.getByText('(Asia/Tokyo)')).toBeInTheDocument()
    expect(postMock).toHaveBeenCalledWith('/api/v1/scans/schedule-preview', {
      schedule_type: 'weekly',
      schedule_day: 1,
      schedule_time: '02:30',
      timezone: 'Asia/Tokyo',
      count: 2,
    })
    expect(items[0].querySelector('time')).toHaveAttribute('datetime', '2099-10-12T02:30:00+09:00')
  })

  it('shows the save rule message inline when the schedule is refused', async () => {
    postMock.mockRejectedValue(
      Object.assign(new Error('schedule fires every 5m0s; the minimum interval is 15m0s'), {
        statusCode: 400,
      })
    )
    renderFresh(
      <SchedulePreview
        request={{
          schedule_type: 'rrule',
          schedule_rrule: 'FREQ=MINUTELY;INTERVAL=5',
          timezone: 'UTC',
        }}
      />
    )
    expect(await screen.findByTestId('schedule-preview-error')).toHaveTextContent(
      'minimum interval'
    )
    expect(screen.queryByRole('listitem')).toBeNull()
  })

  it('says a paused scan runs on these dates only if resumed', async () => {
    postMock.mockResolvedValue({ timezone: 'UTC', occurrences: ['2099-01-01T02:00:00Z'] })
    renderFresh(
      <SchedulePreview
        paused
        request={{ schedule_type: 'daily', schedule_time: '02:00', timezone: 'UTC' }}
      />
    )
    await screen.findAllByRole('listitem')
    expect(screen.getByText('if resumed')).toBeInTheDocument()
  })

  it('renders nothing and asks nothing for a manual scan or without a tenant', async () => {
    const { container } = renderFresh(<SchedulePreview request={null} />)
    expect(container).toBeEmptyDOMElement()
    tenant = null
    renderFresh(<SchedulePreview request={{ schedule_type: 'daily', schedule_time: '02:00' }} />)
    await waitFor(() => expect(postMock).not.toHaveBeenCalled())
  })

  it('says when a rule has no upcoming run', async () => {
    postMock.mockResolvedValue({ timezone: 'UTC', occurrences: [] })
    renderFresh(
      <SchedulePreview
        request={{ schedule_type: 'rrule', schedule_rrule: 'FREQ=DAILY', timezone: 'UTC' }}
      />
    )
    expect(await screen.findByText(/no upcoming runs/)).toBeInTheDocument()
  })
})
