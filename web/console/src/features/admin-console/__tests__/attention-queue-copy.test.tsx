import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { AttentionQueue } from '../components/attention-queue'
import { buildAttention } from '../lib/attention'
import type { AdminOverview } from '../types'

const o = {
  organizations: { total: 1, without_owner: 0, without_owner_sample: [] },
  platform: {
    schema_known: false,
    schema_shipped: 0,
    schema_version: 0,
    schema_dirty: false,
    platform_sensors: { total: 0, online: 0, offline: 0 },
    scan_runs_past_deadline: 0,
    outbox_dead: 0,
    command_oldest_pending_seconds: 0,
    commands_pending: 0,
  },
  security: {
    break_glass_sign_ins_7d: 0,
    failed_admin_actions_24h: 0,
    break_glass_tests_overdue: 1,
  },
  requests: { access_pending: 1, access_oldest_pending_seconds: 86400 },
} as unknown as AdminOverview

describe('attention list copy', () => {
  it('uses real plurals, never "(s)"', () => {
    render(<AttentionQueue items={buildAttention(o, 'readonly')} />)
    expect(
      screen.getByText('1 request for an organization; the oldest has waited 1 day.')
    ).toBeInTheDocument()
    expect(
      screen.getByText('1 emergency-access account not tested in 90 days.')
    ).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('(s)')
  })

  it('is one list with a row per problem and the severity spoken', () => {
    render(<AttentionQueue items={buildAttention(o, 'readonly')} />)
    const list = screen.getByRole('list', { name: 'Needs attention' })
    expect(list.querySelectorAll('li')).toHaveLength(2)
    expect(list.querySelectorAll('[data-severity="warning"]')).toHaveLength(1)
  })
})
