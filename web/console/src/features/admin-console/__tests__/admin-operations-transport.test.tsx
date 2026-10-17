import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { AdminOperations } from '../types'

const state = vi.hoisted(() => ({ data: undefined as unknown }))

vi.mock('@console/features/admin-console/api/use-admin-operations', () => ({
  useAdminOperations: () => ({
    data: state.data,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
}))

import AdminOperationsPage from '@console/app/(console)/operations/page'

function ops(transport?: AdminOperations['sensor_transport']): AdminOperations {
  return {
    build: { version: 'v0.10.0', channel: 'release' },
    schema: { applied: 1, shipped: 1, dirty: false, known: true },
    database: {
      ok: true,
      configured: true,
      latency_ms: 1,
      open_connections: 1,
      in_use: 0,
      idle: 1,
      max_open: 10,
      wait_count: 0,
    },
    redis: { ok: true, configured: true, latency_ms: 1 },
    queues: {
      commands_pending: 0,
      commands_running: 0,
      command_oldest_pending_seconds: 0,
      scan_runs_open: 0,
      scan_runs_past_deadline: 0,
      outbox_pending: 0,
      outbox_failed: 0,
      outbox_dead: 0,
      outbox_oldest_pending_seconds: 0,
    },
    sensors: [],
    controllers: [],
    checked_at: '2026-10-11T00:00:00Z',
    sensor_transport: transport,
  }
}

describe('Operations: sensor connection', () => {
  it('explains why sensors use HTTPS, links the docs and keeps the code secondary', () => {
    state.data = ops({
      mode: 'auto',
      grpc: { state: 'unavailable', reason: 'foreign_certificate' },
    })
    render(<AdminOperationsPage />)
    expect(screen.getByText('Sensor connection')).toBeInTheDocument()
    const note = screen.getByTestId('sensor-transport-note')
    expect(note).toHaveTextContent('The gateway in front of the platform terminates TLS')
    expect(note).toHaveTextContent('Reason code: foreign_certificate')
    expect(screen.getByRole('link', { name: 'How sensors connect' })).toHaveAttribute(
      'href',
      'https://docs.openctem.io/sensors/transport/#what-the-platform-offers'
    )
    expect(note.className).not.toMatch(/warning|destructive/)
  })

  it('shows no note while sensors use gRPC', () => {
    state.data = ops({
      mode: 'auto',
      grpc: { state: 'advertised', endpoint: 'sensors.example.test:443' },
    })
    render(<AdminOperationsPage />)
    expect(screen.getByText('gRPC and HTTPS')).toBeInTheDocument()
    expect(screen.queryByTestId('sensor-transport-note')).not.toBeInTheDocument()
  })

  it('leaves the row out when the API does not report the transport', () => {
    state.data = ops(undefined)
    render(<AdminOperationsPage />)
    expect(screen.queryByText('Sensor connection')).not.toBeInTheDocument()
  })
})
