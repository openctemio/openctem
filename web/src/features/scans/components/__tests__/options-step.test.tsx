import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

let platformOffered = false
let canReadProfiles = true
const profileCalls: unknown[] = []
vi.mock('@/lib/api/platform-hooks', () => ({
  usePlatformScanning: () => ({ offered: platformOffered }),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { ScanProfilesRead: 'scans:profiles:read' },
  useHasPermission: () => canReadProfiles,
}))
vi.mock('@/lib/api/scan-profile-hooks', () => ({
  useScanProfiles: (f: unknown, cfg: { isPaused?: () => boolean }) => {
    profileCalls.push({ f, paused: cfg?.isPaused?.() })
    return {
      data: {
        items: [
          {
            id: 'p1',
            name: 'Gentle',
            quality_gate: {
              enabled: true,
              fail_on_critical: true,
              fail_on_high: false,
              max_critical: 0,
              max_high: -1,
              max_medium: -1,
              max_total: -1,
            },
            description: 'Slow and quiet',
            is_default: false,
          },
        ],
      },
    }
  },
}))

import { OptionsStep } from '../new-scan/options-step'
import { DEFAULT_NEW_SCAN } from '../../types'

Element.prototype.hasPointerCapture ??= () => false
Element.prototype.scrollIntoView ??= () => {}

describe('OptionsStep', () => {
  beforeEach(() => {
    platformOffered = false
    canReadProfiles = true
    profileCalls.length = 0
  })

  it('asks where the scan runs, platform only where offered', async () => {
    const onChange = vi.fn()
    render(<OptionsStep data={DEFAULT_NEW_SCAN} onChange={onChange} />)
    expect(screen.queryByLabelText(/Platform/)).toBeNull()
    await userEvent.click(screen.getByRole('radio', { name: /Organization sensors/ }))
    expect(onChange).toHaveBeenCalledWith({ sensorPreference: 'tenant' })
  })

  it('offers the scan profile on a new scan for a reader of profiles', async () => {
    const onChange = vi.fn()
    render(<OptionsStep data={DEFAULT_NEW_SCAN} onChange={onChange} showProfile />)
    await userEvent.click(screen.getByLabelText('Pass/fail rule (optional)'))
    await userEvent.click(await screen.findByRole('option', { name: 'Gentle' }))
    expect(onChange).toHaveBeenCalledWith({ profileId: 'p1' })
  })

  it('describes the profile as a pass/fail rule, not tool settings or intensity', () => {
    render(
      <OptionsStep data={{ ...DEFAULT_NEW_SCAN, profileId: 'p1' }} onChange={vi.fn()} showProfile />
    )
    expect(screen.getByText(/Fails on critical/)).toBeInTheDocument()
    expect(screen.queryByText(/intensity/i)).toBeNull()
    expect(screen.queryByText(/Tool settings/i)).toBeNull()
  })

  it('does not load profiles without the permission, nor on Edit', () => {
    canReadProfiles = false
    render(<OptionsStep data={DEFAULT_NEW_SCAN} onChange={vi.fn()} showProfile />)
    expect(screen.queryByLabelText('Pass/fail rule (optional)')).toBeNull()
    expect(profileCalls.every((c) => (c as { paused: boolean }).paused)).toBe(true)
  })

  it('keeps job size and retries under Advanced', async () => {
    render(<OptionsStep data={DEFAULT_NEW_SCAN} onChange={vi.fn()} />)
    expect(screen.queryByLabelText('Targets per job')).toBeNull()
    await userEvent.click(screen.getByText(/Advanced: job size/))
    expect(screen.getByLabelText('Targets per job')).toBeInTheDocument()
  })
})
