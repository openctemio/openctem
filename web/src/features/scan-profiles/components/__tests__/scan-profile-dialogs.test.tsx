import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const createProfile = vi.fn()
vi.mock('@/lib/api/scan-profile-hooks', () => ({
  useCreateScanProfile: () => ({ trigger: createProfile, isMutating: false }),
  useUpdateScanProfile: () => ({ trigger: vi.fn(), isMutating: false }),
  invalidateScanProfilesCache: vi.fn(),
}))

import { AddScanProfileDialog } from '../add-scan-profile-dialog'
import { EditScanProfileDialog } from '../edit-scan-profile-dialog'
import { gateSummary } from '../../gate-summary'
import { createDefaultQualityGate, type ScanProfile } from '@/lib/api/scan-profile-types'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const REMOVED = [/intensity/i, /timeout/i, /concurrent/i, /^tools$/i]

describe('scan profile dialogs', () => {
  it('create offers only the pass/fail rule: no intensity, tools, timeout or concurrency', () => {
    render(<AddScanProfileDialog open onOpenChange={vi.fn()} />)
    expect(screen.getByText('Pass/fail rule')).toBeInTheDocument()
    for (const re of REMOVED) expect(screen.queryByText(re)).toBeNull()
  })

  it('a system profile is read-only and offers no Save action', () => {
    const profile = {
      id: 'p',
      name: 'Quick Discovery',
      is_system: true,
      quality_gate: createDefaultQualityGate(),
    } as unknown as ScanProfile
    render(<EditScanProfileDialog open onOpenChange={vi.fn()} profile={profile} />)
    expect(screen.getByText('System profiles cannot be modified.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save changes' })).toBeNull()
  })

  it('summarizes the rule', () => {
    const t = (k: string) => k.split('.').pop() as string
    expect(gateSummary(createDefaultQualityGate(), t)).toBe('off')
    expect(
      gateSummary({ ...createDefaultQualityGate(), enabled: true, fail_on_critical: true }, t)
    ).toBe('failsOn critical')
  })
})
