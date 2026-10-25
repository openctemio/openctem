import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const createProfile = vi.fn()
const updateProfile = vi.fn()
vi.mock('@/lib/api/scan-profile-hooks', () => ({
  useCreateScanProfile: () => ({ trigger: createProfile, isMutating: false }),
  useUpdateScanProfile: () => ({ trigger: updateProfile, isMutating: false }),
  invalidateScanProfilesCache: vi.fn(),
}))

// Owner or admin unless a test says otherwise (the API route gates).
const role = vi.hoisted(() => ({ admin: true }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useCanMutate: () => role.admin,
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

  it('create sends rule_sources (both by default)', async () => {
    createProfile.mockResolvedValue({})
    render(<AddScanProfileDialog open onOpenChange={vi.fn()} />)
    expect(screen.getByText('Detection rules')).toBeInTheDocument()
    await userEvent.type(screen.getAllByRole('textbox')[0], 'Strict')
    await userEvent.click(screen.getByRole('button', { name: /^Create/ }))
    await waitFor(() => expect(createProfile).toHaveBeenCalled())
    expect(createProfile.mock.calls[0][0]).toMatchObject({ name: 'Strict', rule_sources: 'both' })
  })

  it('edit sends the profile rule_sources', async () => {
    updateProfile.mockResolvedValue({})
    const profile = {
      id: 'p',
      name: 'Org rules',
      is_system: false,
      rule_sources: 'tenant',
      quality_gate: createDefaultQualityGate(),
    } as unknown as ScanProfile
    render(<EditScanProfileDialog open onOpenChange={vi.fn()} profile={profile} />)
    expect(screen.getByRole('combobox', { name: 'Detection rules' })).toHaveTextContent(
      'Organization templates only'
    )
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(updateProfile).toHaveBeenCalled())
    expect(updateProfile.mock.calls[0][0]).toMatchObject({ rule_sources: 'tenant' })
  })

  it('a member cannot change the pass/fail rule or create the default profile', async () => {
    role.admin = false
    try {
      const profile = {
        id: 'p',
        name: 'Mine',
        is_system: false,
        quality_gate: { ...createDefaultQualityGate(), enabled: true, fail_on_critical: true },
      } as unknown as ScanProfile
      const { unmount } = render(
        <EditScanProfileDialog open onOpenChange={vi.fn()} profile={profile} />
      )
      expect(
        screen.getByText('Only an owner or admin can change the pass/fail rule.')
      ).toBeInTheDocument()
      for (const sw of screen.getAllByRole('switch')) expect(sw).toBeDisabled()
      unmount()

      createProfile.mockClear()
      createProfile.mockResolvedValue({})
      render(<AddScanProfileDialog open onOpenChange={vi.fn()} />)
      expect(screen.queryByText('Use this profile for new scans that do not choose one')).toBeNull()
      await userEvent.type(screen.getAllByRole('textbox')[0], 'Lax')
      await userEvent.click(screen.getByRole('button', { name: /^Create/ }))
      await waitFor(() => expect(createProfile).toHaveBeenCalled())
      expect(createProfile.mock.calls[0][0]).toMatchObject({ is_default: false })
    } finally {
      role.admin = true
    }
  })

  it('summarizes the rule', () => {
    const t = (k: string) => k.split('.').pop() as string
    expect(gateSummary(createDefaultQualityGate(), t)).toBe('off')
    expect(
      gateSummary({ ...createDefaultQualityGate(), enabled: true, fail_on_critical: true }, t)
    ).toBe('failsOn critical')
  })
})
