import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import type { ScanConfig } from '@/lib/api/scan-types'
import { ScheduleCell, formatNextRun } from '../schedule-cell'

let canWrite = true
vi.mock('@/lib/permissions', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/permissions')>()
  return { ...actual, useHasPermission: () => canWrite }
})

function config(over: Partial<ScanConfig>): ScanConfig {
  return {
    id: 's1',
    tenant_id: 't1',
    name: 'Scan',
    scan_type: 'single',
    targets_per_job: 1,
    schedule_type: 'daily',
    schedule_timezone: 'UTC',
    run_on_tenant_runner: false,
    sensor_preference: 'auto',
    timeout_seconds: 3600,
    max_retries: 0,
    retry_backoff_seconds: 60,
    status: 'active',
    total_runs: 0,
    successful_runs: 0,
    failed_runs: 0,
    created_at: '',
    updated_at: '',
    ...over,
  }
}

describe('ScheduleCell', () => {
  it('a manual scan has no switch: "Active" meant nothing for it', () => {
    render(<ScheduleCell config={config({ schedule_type: 'manual' })} onToggle={vi.fn()} />)
    expect(screen.getByText('Manual')).toBeInTheDocument()
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
  })

  it('a scheduled scan has the schedule switch and its next run', () => {
    const next = new Date(Date.now() + 3 * 3600 * 1000 + 60000).toISOString()
    render(<ScheduleCell config={config({ next_run_at: next })} onToggle={vi.fn()} />)
    const toggle = screen.getByRole('switch', { name: 'Turn the schedule off' })
    expect(toggle).toBeChecked()
    expect(screen.getByText(/Next: in 3 hours/)).toBeInTheDocument()
  })

  it('turning it off pauses the scan', async () => {
    const onToggle = vi.fn().mockResolvedValue(undefined)
    const c = config({})
    render(<ScheduleCell config={c} onToggle={onToggle} />)
    fireEvent.click(screen.getByRole('switch'))
    await waitFor(() => expect(onToggle).toHaveBeenCalledWith('pause', c))
  })

  it('a paused schedule reads off; a disabled scan locks the switch', () => {
    const { rerender } = render(
      <ScheduleCell config={config({ status: 'paused' })} onToggle={vi.fn()} />
    )
    expect(screen.getByRole('switch')).not.toBeChecked()
    expect(screen.getByText('Schedule off')).toBeInTheDocument()
    rerender(<ScheduleCell config={config({ status: 'disabled' })} onToggle={vi.fn()} />)
    expect(screen.getByRole('switch')).toBeDisabled()
  })

  it('without scans:write the switch is read-only', () => {
    canWrite = false
    render(<ScheduleCell config={config({})} onToggle={vi.fn()} />)
    expect(screen.getByRole('switch')).toBeDisabled()
    canWrite = true
  })
})

describe('formatNextRun', () => {
  it('words the next run', () => {
    const now = Date.parse('2026-10-07T00:00:00Z')
    expect(formatNextRun('2026-10-06T23:00:00Z', now)).toBe('Overdue')
    expect(formatNextRun('2026-10-09T01:00:00Z', now)).toBe('in 2 days')
    expect(formatNextRun(undefined, now)).toBeNull()
  })
})
