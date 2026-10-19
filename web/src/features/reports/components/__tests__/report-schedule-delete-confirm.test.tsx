import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ReportSchedulesSection } from '../report-schedules-section'

const deleteSchedule = vi.hoisted(() => vi.fn(() => Promise.resolve()))
vi.mock('../../hooks/use-report-schedules', () => ({
  useReportSchedules: () => ({
    schedules: [
      {
        id: 's1',
        name: 'Weekly exec digest',
        report_type: 'summary',
        format: 'pdf',
        cron_expression: '0 8 * * 1',
        timezone: 'UTC',
        recipients: [],
        delivery_channel: 'email',
        is_active: true,
        run_count: 0,
        created_at: '2026-10-01T00:00:00Z',
        created_by: 'u-sam',
        created_by_name: 'Sam Member',
        can_manage: true,
        recipient_count: 0,
      },
      {
        id: 's2',
        name: 'Owner executive summary',
        report_type: 'executive_summary',
        format: 'html',
        cron_expression: '0 8 * * 1',
        timezone: 'UTC',
        recipients: [],
        delivery_channel: 'email',
        is_active: true,
        run_count: 3,
        created_at: '2026-10-01T00:00:00Z',
        created_by: 'u-alex',
        created_by_name: 'Alex Owner',
        can_manage: false,
        recipient_count: 2,
      },
    ],
    isLoading: false,
    error: undefined,
    createSchedule: vi.fn(),
    toggleSchedule: vi.fn(),
    deleteSchedule,
  }),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

describe('Report schedules delete', () => {
  it('asks first and names the schedule', async () => {
    render(<ReportSchedulesSection />)
    await userEvent.click(screen.getByRole('button', { name: 'Delete Weekly exec digest' }))
    expect(deleteSchedule).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete the schedule "Weekly exec digest"?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(deleteSchedule).toHaveBeenCalledWith('s1'))
  })

  // Another member's schedule (the API says can_manage = false) shows its
  // owner, state and recipient count but no toggle or delete.
  it('shows no toggle or delete on a schedule the viewer cannot manage', () => {
    render(<ReportSchedulesSection />)
    expect(screen.getByText('Alex Owner')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete Owner executive summary' })).toBeNull()
    expect(screen.queryByRole('switch', { name: 'Pause Owner executive summary' })).toBeNull()
    const row = screen.getByText('Owner executive summary').closest('tr')!
    expect(within(row).getByText('2')).toBeInTheDocument()
    expect(within(row).getByText('Active')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Pause Weekly exec digest' })).toBeInTheDocument()
  })
})
