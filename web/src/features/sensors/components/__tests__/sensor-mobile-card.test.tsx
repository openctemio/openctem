import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import type { Sensor } from '@/lib/api/sensor-types'
import { TEST_SENSOR_KEY_PREFIX } from '@/test/sensor-keys'

import { SensorMobileCard } from '../sensor-mobile-card'

const NOW = new Date('2026-10-31T03:42:00Z').getTime()

const base: Sensor = {
  id: 's1',
  tenant_id: 't',
  name: 'ssi-sensor',
  type: 'worker',
  capabilities: [],
  effective: { tools: ['nuclei'], capabilities: [], max_concurrent_jobs: 5 },
  execution_mode: 'daemon',
  status: 'active',
  health: 'online',
  api_key_prefix: TEST_SENSOR_KEY_PREFIX,
  cpu_percent: 0,
  memory_percent: 0,
  max_concurrent_jobs: 5,
  current_jobs: 0,
  labels: {},
  config: {},
  metadata: {},
  total_findings: 0,
  total_scans: 0,
  error_count: 0,
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
  last_seen_at: new Date(NOW - 14_000).toISOString(),
  version: 'v0.29.1',
}

function renderCard(over: Partial<Sensor>) {
  render(<SensorMobileCard sensor={{ ...base, ...over }} now={NOW} channel={{}} onOpen={vi.fn()} />)
}

describe('SensorMobileCard', () => {
  it('says why a degraded sensor takes no work when its storage is full', () => {
    renderCard({
      state: 'degraded',
      health_reasons: [
        { code: 'stopped_claiming', severity: 'critical', message: 'Local storage is full.' },
      ],
      local_store: {
        level: 'high',
        stop_claiming: true,
        reason: '9 % of the volume free, below 15 %',
        total_bytes: 0,
        disk_level: 'ok',
        reported_at: null,
      },
    })
    expect(screen.getByText('Degraded')).toBeInTheDocument()
    expect(screen.getByText('takes no new jobs: storage full')).toHaveClass('text-destructive')
  })

  it('words any other reason of a degraded sensor with the fleet words', () => {
    renderCard({
      state: 'degraded',
      health_reasons: [{ code: 'control_slow', severity: 'warning', message: 'Slow loop.' }],
    })
    expect(screen.getByText('heartbeat')).toHaveClass('text-warning')
  })

  it('adds nothing to an online sensor', () => {
    renderCard({ state: 'online', health_reasons: [] })
    expect(screen.queryByText(/storage full/)).toBeNull()
    expect(screen.getByText('0/5 jobs')).toBeInTheDocument()
  })
})
