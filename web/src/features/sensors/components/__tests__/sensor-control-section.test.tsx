import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { SensorControlSection } from '../sensor-control-section'

const NOW = new Date('2026-10-02T12:00:00Z').getTime()

describe('SensorControlSection', () => {
  it('renders nothing when the sensor reports no control channel', () => {
    const { container } = render(<SensorControlSection sensor={{ control: null }} now={NOW} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the interval, gap, lag, build, round trip and losses', () => {
    render(
      <SensorControlSection
        sensor={{
          control: {
            interval_s: 30,
            gap_s: 30.004,
            lag_ms: 1,
            build_ms: 3,
            rtt_ms: 9,
            failures: 0,
            reported_at: new Date(NOW - 4000).toISOString(),
          },
          heartbeat_due_at: new Date(NOW + 26_000).toISOString(),
          heartbeat_interval_seconds: 30,
        }}
        now={NOW}
      />
    )
    expect(screen.getByRole('region', { name: 'Control channel' })).toBeInTheDocument()
    expect(screen.getByText('30s')).toBeInTheDocument()
    expect(screen.getByText('next due in 26s')).toBeInTheDocument()
    expect(screen.getByText('30.0s')).toBeInTheDocument()
    expect(screen.getByText('1 ms')).toBeInTheDocument()
    expect(screen.getByText('3 ms')).toBeInTheDocument()
    expect(screen.getByText('9 ms')).toBeInTheDocument()
    expect(screen.getByText('Reported by the sensor 4s ago.')).toBeInTheDocument()
    expect(screen.queryByText('more than 1.5 intervals')).not.toBeInTheDocument()
  })

  it('flags a late gap and a slow loop', () => {
    render(
      <SensorControlSection
        sensor={{
          control: {
            interval_s: 30,
            gap_s: 46,
            lag_ms: 5200,
            build_ms: 7000,
            rtt_ms: 120,
            failures: 2,
            reported_at: null,
          },
        }}
        now={NOW}
      />
    )
    expect(screen.getByText('more than 1.5 intervals')).toBeInTheDocument()
    expect(screen.getByText('5.2s')).toHaveClass('text-warning')
    expect(screen.getByText('7.0s')).toHaveClass('text-warning')
    expect(screen.getByText('2')).toHaveClass('text-warning')
  })
})
