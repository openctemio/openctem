import { useState } from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { ScheduleStep } from '../schedule-step'
import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../../../types'

// "Run now" posts /trigger after the create, and that needs scans:execute on
// top of the scans:write that creates the scan: a write-only member always
// ended on "Created but not started" with a 403.
let granted: string[] = []
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useHasPermission: (p: string) => granted.includes(p),
}))
vi.mock('../../schedule-preview', () => ({ SchedulePreview: () => null }))
vi.mock('../../timezone-select', () => ({ TimezoneSelect: () => null }))

function Harness() {
  const [data, setData] = useState<NewScanFormData>(DEFAULT_NEW_SCAN)
  return (
    <>
      <ScheduleStep data={data} onChange={(p) => setData({ ...data, ...p })} offerSaveOnly />
      <output data-testid="mode">
        {data.schedule.runImmediately ? 'now' : data.schedule.saveOnly ? 'save' : 'later'}
      </output>
    </>
  )
}

describe('ScheduleStep run now', () => {
  it('disables Run now and defaults to save-only for a write-only user', () => {
    granted = ['scans:write']
    render(<Harness />)
    expect(screen.getByRole('radio', { name: /Run immediately/ })).toBeDisabled()
    expect(screen.getByText(/scans:execute/)).toBeInTheDocument()
    expect(screen.getByTestId('mode')).toHaveTextContent('save')
  })

  it('keeps Run now on for a user who may execute', () => {
    granted = ['scans:write', 'scans:execute']
    render(<Harness />)
    expect(screen.getByRole('radio', { name: /Run immediately/ })).toBeEnabled()
    expect(screen.getByTestId('mode')).toHaveTextContent('now')
  })
})
