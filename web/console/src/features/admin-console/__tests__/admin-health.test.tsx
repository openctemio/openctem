import { describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { jobNeedsAttention, sortJobs } from '../lib/operations'
import { daysLeft, formatBytes, levelKey, levelTone } from '../lib/system'
import type { AdminSystem } from '../types'

const state = vi.hoisted(() => ({ data: undefined as unknown, ops: undefined as unknown }))

vi.mock('@console/features/admin-console/api/use-admin-operations', () => ({
  useAdminOperations: () => ({
    data: state.ops,
    error: undefined,
    isLoading: !state.ops,
    mutate: vi.fn(),
  }),
}))

vi.mock('@console/features/admin-console/api/use-admin-system', () => ({
  useAdminSystem: () => ({
    data: state.data,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
}))

// The tab lives in the URL (?tab=); a local state stands in for the router.
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (_key: string, fallback: string) => useState(fallback),
}))

import AdminHealthPage from '@console/app/(console)/health/page'

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

describe('Health page', () => {
  it('shows each service, volume, backup, certificate and version', () => {
    state.data = system()
    render(<AdminHealthPage />)
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
    render(<AdminHealthPage />)
    expect(screen.getByText(/No backup status is reported/)).toBeInTheDocument()
  })

  it('offers no action: no button changes the host', () => {
    state.data = system()
    render(<AdminHealthPage />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('merges the host and API views once: schema, queues and jobs, no second version block', async () => {
    state.data = system()
    state.ops = {
      build: { version: 'v0.10.0', commit: 'abc1234', channel: 'release' },
      schema: { applied: 7, shipped: 9, dirty: false, known: true },
      database: {
        ok: true,
        configured: true,
        latency_ms: 1,
        open_connections: 2,
        in_use: 1,
        idle: 1,
        max_open: 25,
        wait_count: 0,
      },
      redis: { ok: true, configured: true, latency_ms: 1 },
      queues: {
        commands_pending: 4,
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
      checked_at: '2026-10-17T12:00:00Z',
    }
    const user = userEvent.setup()
    render(<AdminHealthPage />)
    // Summary first: the schema and the build with the services.
    expect(screen.getByText('Database schema')).toBeInTheDocument()
    expect(screen.getByText(/abc1234/)).toBeInTheDocument()
    expect(screen.getByText(/Pool 1 in use of 2 open/)).toBeInTheDocument()
    expect(screen.queryByText('Version')).not.toBeInTheDocument()
    expect(screen.queryByText('Work queues')).not.toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: /Queues and sensors/ }))
    expect(screen.getByText('Work queues')).toBeInTheDocument()
    expect(screen.getAllByText('Sensor fleet')).toHaveLength(1)
    state.ops = undefined
  })

  it('lists the background jobs that stopped or fail first, the rest behind Show all', async () => {
    state.data = system()
    state.ops = {
      build: { version: 'v0.10.0', commit: 'abc1234', channel: 'release' },
      schema: { applied: 9, shipped: 9, dirty: false, known: true },
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
      controllers: [
        { name: 'audit_retention', running: true, errors_total: 0 },
        { name: 'feed_sync', running: true, errors_total: 4 },
        { name: 'outbox_relay', running: false, errors_total: 0 },
        { name: 'session_purge', running: true, errors_total: 0 },
      ],
      checked_at: '2026-10-17T12:00:00Z',
    }
    const user = userEvent.setup()
    render(<AdminHealthPage />)
    const jobsTab = screen.getByRole('tab', { name: /Background jobs/ })
    // The tab counts the jobs to look at.
    expect(within(jobsTab).getByText('2')).toBeInTheDocument()
    await user.click(jobsTab)
    expect(screen.getByText(/2 background jobs stopped or failed/)).toBeInTheDocument()
    expect(screen.getAllByText('feed_sync').length).toBeGreaterThan(0)
    expect(screen.getAllByText('outbox_relay').length).toBeGreaterThan(0)
    expect(screen.queryByText('session_purge')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Show all (4)' }))
    expect(screen.getAllByText('session_purge').length).toBeGreaterThan(0)
    state.ops = undefined
  })

  it('sorts jobs: stopped or failing first, most errors first, then by name', () => {
    const jobs = [
      { name: 'b', running: true, errors_total: 0 },
      { name: 'a', running: true, errors_total: 0 },
      { name: 'c', running: true, errors_total: 1 },
      { name: 'd', running: false, errors_total: 0 },
      { name: 'e', running: true, errors_total: 9 },
    ]
    expect(sortJobs(jobs).map((j) => j.name)).toEqual(['e', 'c', 'd', 'a', 'b'])
    expect(jobNeedsAttention({ name: 'x', running: true, errors_total: 0 })).toBe(false)
  })
})
