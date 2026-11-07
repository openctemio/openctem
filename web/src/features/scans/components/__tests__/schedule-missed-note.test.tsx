import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import type { ScanConfig } from '@/lib/api/scan-types'
import { hasScheduleMissed, missedReasonLabel } from '../../lib/schedule-missed'
import { ScheduleMissedNote } from '../schedule-missed-note'

const trigger = vi.fn()
vi.mock('../../hooks/use-scan-trigger', () => ({
  useScanTrigger: () => ({ trigger, isTriggering: () => false, dialog: null }),
}))
vi.mock('@/lib/permissions', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    useHasPermission: () => true,
    Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  }
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

describe('schedule missed mapping', () => {
  it('maps the reason codes and falls back for an unknown one', () => {
    expect(missedReasonLabel('platform_unavailable')).toMatch(/platform was unavailable/)
    expect(missedReasonLabel('once_grace_exceeded')).toMatch(/one-off/)
    expect(missedReasonLabel('something_new')).toMatch(/skipped/)
    expect(missedReasonLabel(undefined)).toMatch(/skipped/)
  })

  it('shows only for a scheduled, enabled scan that has a missed run', () => {
    const at = '2026-11-07T01:00:00Z'
    expect(hasScheduleMissed(config({ last_missed_at: at }))).toBe(true)
    expect(hasScheduleMissed(config({}))).toBe(false)
    expect(hasScheduleMissed(config({ last_missed_at: at, schedule_type: 'manual' }))).toBe(false)
    expect(hasScheduleMissed(config({ last_missed_at: at, status: 'disabled' }))).toBe(false)
  })
})

describe('ScheduleMissedNote', () => {
  it('renders nothing without a missed run', () => {
    const { container } = render(<ScheduleMissedNote config={config({})} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the note with Run now, which triggers the scan', () => {
    const c = config({
      last_missed_at: '2026-11-07T01:00:00Z',
      last_missed_reason: 'platform_unavailable',
    })
    render(<ScheduleMissedNote config={c} />)
    expect(screen.getByText(/^Missed /)).toBeInTheDocument()
    screen.getByRole('button', { name: 'Run now' }).click()
    expect(trigger).toHaveBeenCalledWith(c)
  })

  it('omits the button in the list cell', () => {
    render(
      <ScheduleMissedNote
        config={config({ last_missed_at: '2026-11-07T01:00:00Z' })}
        showRunNow={false}
      />
    )
    expect(screen.queryByRole('button')).toBeNull()
  })
})
