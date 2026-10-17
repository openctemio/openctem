import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { daysLeft, formatBytes, levelKey, levelTone } from '../lib/system'
import type { AdminSystem } from '../types'

const state = vi.hoisted(() => ({ data: undefined as unknown }))

vi.mock('@console/features/admin-console/api/use-admin-system', () => ({
  useAdminSystem: () => ({
    data: state.data,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
}))

import AdminSystemPage from '@console/app/(console)/system/page'

function system(patch: Partial<AdminSystem> = {}): AdminSystem {
  return {
    services: [
      { name: 'api', configured: true, ok: true, latency_ms: 0 },
      { name: 'postgres', configured: true, ok: true, latency_ms: 1.5 },
      { name: 'redis', configured: true, ok: false, latency_ms: 0, code: 'unreachable' },
      { name: 'web', configured: false, ok: false, latency_ms: 0 },
      { name: 'gateway', configured: true, ok: false, latency_ms: 0, code: 'unhealthy' },
      { name: 'sensors', configured: true, ok: true, latency_ms: 0, detail: 3 },
    ],
    storage: {
      volumes: [
        {
          name: 'attachments',
          ok: true,
          total_bytes: 100 * 1024 ** 3,
          used_bytes: 92 * 1024 ** 3,
          free_bytes: 8 * 1024 ** 3,
          free_ratio: 0.08,
          level: 2,
        },
      ],
      database_bytes: 5 * 1024 ** 3,
      database_ok: true,
    },
    backup: {
      reported: true,
      last_success_at: '2026-10-16T01:00:00Z',
      age_seconds: 108000,
      level: 1,
    },
    certificates: [
      {
        name: 'sensor-ca',
        ok: true,
        not_after: '2036-01-01T00:00:00Z',
        expires_in_seconds: 86400 * 400,
        level: 0,
      },
      {
        name: 'edge',
        ok: true,
        not_after: '2026-10-20T00:00:00Z',
        expires_in_seconds: 86400 * 3,
        level: 2,
      },
    ],
    version: {
      running: 'v0.10.0',
      channel: 'release',
      check: {
        enabled: true,
        configured: true,
        update_available: true,
        latest: 'v0.11.0',
        advisories: 0,
        stale: false,
      },
    },
    level: 2,
    checked_at: '2026-10-17T12:00:00Z',
    ...patch,
  }
}

describe('System page helpers', () => {
  it('maps levels to tones and keys', () => {
    expect(levelTone(0)).toBe('success')
    expect(levelTone(1)).toBe('warning')
    expect(levelTone(2)).toBe('destructive')
    expect(levelKey(2)).toBe('critical')
  })
  it('formats sizes and days', () => {
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(8 * 1024 ** 3)).toBe('8.0 GiB')
    expect(formatBytes(-1)).toBe('-')
    expect(daysLeft(86400 * 3 + 5)).toBe(3)
    expect(daysLeft(undefined)).toBeNull()
  })
})

describe('System page', () => {
  it('shows each service, volume, backup, certificate and version', () => {
    state.data = system()
    render(<AdminSystemPage />)
    expect(screen.getByText('Connected sensors')).toBeInTheDocument()
    expect(screen.getByText('3 online')).toBeInTheDocument()
    expect(screen.getByText('Not configured')).toBeInTheDocument()
    expect(screen.getByText('Unhealthy')).toBeInTheDocument()
    expect(screen.getByText('attachments')).toBeInTheDocument()
    expect(screen.getByText('8% free')).toBeInTheDocument()
    expect(screen.getByText('5.0 GiB')).toBeInTheDocument()
    expect(screen.getByText('Older than 26 h')).toBeInTheDocument()
    expect(screen.getByText('Expires in 3 days')).toBeInTheDocument()
    expect(screen.getByText('v0.11.0')).toBeInTheDocument()
    expect(screen.getByText('Update available')).toBeInTheDocument()
  })

  it('says so when no backup status is reported', () => {
    state.data = system({ backup: { reported: false, level: 0 } })
    render(<AdminSystemPage />)
    expect(screen.getByText(/No backup status is reported/)).toBeInTheDocument()
  })

  it('offers no action: no button changes the host', () => {
    state.data = system()
    render(<AdminSystemPage />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })
})
