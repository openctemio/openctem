import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { summarize, SignupEventsPanel } from '../components/signup-events-panel'
import { parseDomains, SignupAlertsForm } from '../components/signup-alerts-form'
import type { SignupDailyCount, SignupEventList } from '../api/use-signup-events'

const mocks = vi.hoisted(() => ({
  list: { data: undefined as SignupEventList | undefined },
  daily: { data: [] as SignupDailyCount[] },
}))

vi.mock('../api/use-signup-events', async (orig) => ({
  ...(await orig<typeof import('../api/use-signup-events')>()),
  useSignupEvents: () => ({
    data: mocks.list.data,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useSignupDaily: () => ({
    data: mocks.daily.data,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

describe('summarize', () => {
  it('totals today, 7 and 30 days per kind', () => {
    const counts: SignupDailyCount[] = [
      { day: '2026-10-18', kind: 'account_created', count: 2 },
      { day: '2026-10-15', kind: 'account_created', count: 3 },
      { day: '2026-10-01', kind: 'account_created', count: 4 },
      { day: '2026-09-01', kind: 'account_created', count: 100 },
      { day: '2026-10-18', kind: 'access_requested', count: 1 },
    ]
    const s = summarize(counts, '2026-10-18')
    expect(s.account_created).toEqual({ today: 2, week: 5, month: 9 })
    expect(s.access_requested).toEqual({ today: 1, week: 1, month: 1 })
    expect(s.organization_created).toEqual({ today: 0, week: 0, month: 0 })
  })
})

describe('parseDomains', () => {
  it('lower-cases, strips @ and trailing dots, de-duplicates and sorts', () => {
    expect(parseDomains('Gmail.com\n@gmail.com, example.org.\n\n')).toEqual([
      'example.org',
      'gmail.com',
    ])
  })
})

describe('SignupEventsPanel', () => {
  beforeEach(() => {
    mocks.daily.data = []
  })

  it('shows domain and network only, and links the organization', () => {
    mocks.list.data = {
      data: [
        {
          id: 1,
          kind: 'organization_created',
          source: 'self_service',
          email_domain: 'example.com',
          ip_prefix: '198.51.100.0/24',
          tenant_id: 'aaaaaaaa-0000-0000-0000-000000000001',
          occurred_at: new Date().toISOString(),
        },
      ],
      total: 1,
      page: 1,
      per_page: 50,
      total_pages: 1,
    }
    render(<SignupEventsPanel />)
    expect(screen.getByText('example.com')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.0/24')).toBeInTheDocument()
    expect(screen.getByText('Created by a member')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open' })).toHaveAttribute(
      'href',
      '/organizations/aaaaaaaa-0000-0000-0000-000000000001'
    )
  })

  it('has an empty state', () => {
    mocks.list.data = { data: [], total: 0, page: 1, per_page: 50, total_pages: 0 }
    render(<SignupEventsPanel />)
    expect(screen.getByText('No sign-ups yet')).toBeInTheDocument()
  })
})

describe('SignupAlertsForm', () => {
  const thresholds = {
    per_ip_prefix: 10,
    per_email_domain: 20,
    window_minutes: 60,
    ignored_domains: [],
  }

  it('read-only for a non-super admin', () => {
    render(<SignupAlertsForm thresholds={thresholds} canEdit={false} onSave={vi.fn()} />)
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('Per network (/24 or /48)')).toBeDisabled()
  })

  it('saves with a reason and a code', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    render(<SignupAlertsForm thresholds={thresholds} canEdit onSave={onSave} />)
    const save = screen.getByRole('button', { name: 'Save' })
    expect(save).toBeDisabled()
    const prefix = screen.getByLabelText('Per network (/24 or /48)')
    await userEvent.clear(prefix)
    await userEvent.type(prefix, '5')
    await userEvent.type(screen.getByLabelText('Ignored email domains'), 'Gmail.com')
    await userEvent.click(save)
    await userEvent.type(screen.getByLabelText('Reason'), 'launch')
    await userEvent.type(screen.getByLabelText(/code/i), '123456')
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(onSave).toHaveBeenCalledWith(
      {
        per_ip_prefix: 5,
        per_email_domain: 20,
        window_minutes: 60,
        ignored_domains: ['gmail.com'],
      },
      'launch',
      '123456'
    )
  })

  it('refuses a window below 5 minutes', async () => {
    render(<SignupAlertsForm thresholds={thresholds} canEdit onSave={vi.fn()} />)
    const w = screen.getByLabelText('Window (minutes)')
    await userEvent.clear(w)
    await userEvent.type(w, '1')
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })
})
