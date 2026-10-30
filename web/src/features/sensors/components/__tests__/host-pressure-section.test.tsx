import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import type { SensorPressure } from '@/lib/api/sensor-types'

import { HostPressureSection } from '../host-pressure-section'

const base: SensorPressure = {
  level: 'elevated',
  reasons: ['cpu', 'io', 'bogus'],
  level_seconds: 120,
  psi: true,
  cpu_some_avg10: 12.5,
  mem_some_avg10: 0,
  mem_full_avg10: 0,
  io_some_avg10: 3.1,
  io_full_avg10: 0,
  load_per_cpu: 0.8,
  fd_used_pct: 4.2,
  host_cpu_busy_pct: 96,
  foreign_cpu_pct: 81,
  cpu_throttled_pct: 7,
  noisy_neighbor: false,
}

function sensorWith(p: SensorPressure | null) {
  return {
    load: {
      reported_at: null,
      fresh: true,
      resources: { pressure: p },
      capacity: {
        slots_total: 4,
        slots_free: 3,
        active_jobs: 1,
        launches_held: 2,
        transient: {
          handshake_timeouts: 0,
          slow_starts: 1,
          oom_kills: 0,
          start_eagain: 0,
          retried: 1,
          recovered: 1,
        },
      },
    },
  }
}

describe('HostPressureSection', () => {
  it('renders nothing when the sensor reports no pressure', () => {
    const { container } = render(<HostPressureSection sensor={sensorWith(null)} />)
    expect(container).toBeEmptyDOMElement()
    const none = render(<HostPressureSection sensor={{ load: null }} />)
    expect(none.container).toBeEmptyDOMElement()
  })

  it('shows the level, readable reasons, stalls, held launches and retries', () => {
    render(<HostPressureSection sensor={sensorWith(base)} />)
    expect(screen.getByTestId('host-pressure-level')).toHaveTextContent('Elevated')
    expect(screen.getByText('CPU stalls')).toBeInTheDocument()
    expect(screen.getByText('Disk stalls')).toBeInTheDocument()
    expect(screen.queryByText('bogus')).not.toBeInTheDocument()
    expect(screen.getByText('12.5%')).toBeInTheDocument()
    expect(screen.getByText('7%')).toBeInTheDocument()
    expect(screen.getByText('0.80')).toBeInTheDocument()
    expect(screen.getByText('1 retried, 1 recovered')).toBeInTheDocument()
  })

  it('treats an unknown level as normal', () => {
    render(<HostPressureSection sensor={sensorWith({ ...base, level: '', reasons: null })} />)
    expect(screen.getByTestId('host-pressure-level')).toHaveTextContent('Normal')
  })

  it('warns about a noisy neighbour only when reported', () => {
    const { rerender } = render(<HostPressureSection sensor={sensorWith(base)} />)
    expect(screen.queryByTestId('host-pressure-noisy')).not.toBeInTheDocument()
    rerender(<HostPressureSection sensor={sensorWith({ ...base, noisy_neighbor: true })} />)
    expect(screen.getByTestId('host-pressure-noisy')).toHaveTextContent(
      'Other programs on this host use most of its CPU.'
    )
  })
})
