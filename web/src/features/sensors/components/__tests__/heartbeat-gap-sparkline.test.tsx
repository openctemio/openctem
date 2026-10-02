import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import type { SensorHeartbeatHistoryResponse } from '@/lib/api/sensor-types'

import { HeartbeatGapSparkline, bucketIsLate, heartbeatSlots } from '../heartbeat-gap-sparkline'
import { SensorControlSection } from '../sensor-control-section'

const NOW = new Date('2026-10-02T12:07:00Z').getTime()

function bucket(
  at: string,
  maxGap: number,
  extra: Partial<SensorHeartbeatHistoryResponse['buckets'][number]> = {}
) {
  return {
    at,
    beats: 30,
    avg_gap_s: 30,
    max_gap_s: maxGap,
    interval_s: 30,
    max_lag_ms: 0,
    failures: 0,
    ...extra,
  }
}

const history: SensorHeartbeatHistoryResponse = {
  bucket_seconds: 900,
  hours: 24,
  buckets: [
    bucket('2026-10-02T11:30:00Z', 31),
    bucket('2026-10-02T11:45:00Z', 95, { failures: 2 }),
    bucket('2026-10-02T12:00:00Z', 30),
  ],
}

describe('heartbeatSlots', () => {
  it('lays the last 24 h out in 96 aligned slots, oldest first, with the buckets in theirs', () => {
    const slots = heartbeatSlots(history, NOW)
    expect(slots).toHaveLength(96)
    expect(new Date(slots[95].start).toISOString()).toBe('2026-10-02T12:00:00.000Z')
    expect(new Date(slots[0].start).toISOString()).toBe('2026-10-01T12:15:00.000Z')
    expect(slots[94].bucket?.max_gap_s).toBe(95)
    expect(slots[93].bucket?.max_gap_s).toBe(31)
    expect(slots[92].bucket).toBeNull()
  })

  it('flags a bucket whose largest gap is above 1.5 intervals as late', () => {
    expect(bucketIsLate(history.buckets[1])).toBe(true)
    expect(bucketIsLate(history.buckets[0])).toBe(false)
  })
})

describe('HeartbeatGapSparkline', () => {
  it('draws one bar per slot, late ones as warnings, and says so in its label', () => {
    const { container } = render(<HeartbeatGapSparkline history={history} now={NOW} />)
    const img = screen.getByRole('img')
    expect(img).toHaveAccessibleName(
      /3 of 96 15-minute slots had heartbeats, 1 late, 93 without any/
    )
    expect(container.querySelectorAll('rect')).toHaveLength(96)
    expect(container.querySelectorAll('rect[data-late]')).toHaveLength(1)
    expect(container.querySelector('rect[data-late] title')?.textContent).toMatch(
      /largest gap 1m .*2 lost/
    )
  })

  it('says when there is no history yet', () => {
    render(<HeartbeatGapSparkline history={{ ...history, buckets: [] }} now={NOW} />)
    expect(screen.getByText('No heartbeat history yet.')).toBeInTheDocument()
  })
})

describe('SensorControlSection with history', () => {
  it('shows the sparkline for a sensor that reports no control block (older SDK)', () => {
    render(<SensorControlSection sensor={{ control: null }} now={NOW} history={history} />)
    expect(screen.getByRole('region', { name: 'Control channel' })).toBeInTheDocument()
    expect(screen.getByText('Heartbeats, last 24 hours')).toBeInTheDocument()
    expect(screen.queryByText('Timer lag')).not.toBeInTheDocument()
  })

  it('renders nothing with neither control nor history', () => {
    const { container } = render(
      <SensorControlSection
        sensor={{ control: null }}
        now={NOW}
        history={{ ...history, buckets: [] }}
      />
    )
    expect(container).toBeEmptyDOMElement()
  })
})
