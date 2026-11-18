import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { CloneScanDialog } from '../clone-scan-dialog'
import type { ScanConfig } from '@/lib/api/scan-types'

const cloneScan = vi.fn()
const cloneIds: string[] = []
vi.mock('@/lib/api/scan-hooks', () => ({
  useCloneScanConfig: (id: string) => {
    cloneIds.push(id)
    return { trigger: cloneScan, isMutating: false }
  },
  invalidateScanConfigsCache: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn() } }))

const scan = {
  id: 'cfg-1',
  name: 'Weekly external',
  scan_type: 'workflow',
  schedule_type: 'weekly',
  status: 'active',
  targets: ['a.example.com', 'b.example.com'],
  asset_group_ids: ['g1'],
  tags: ['external', 'pci'],
} as unknown as ScanConfig

describe('CloneScanDialog', () => {
  beforeEach(() => {
    cloneScan.mockReset()
    cloneIds.length = 0
  })

  it('offers the copy name and what is cloned, and sends one clone request', async () => {
    cloneScan.mockResolvedValue({ id: 'cfg-2', name: 'Weekly external (Copy)' })
    const onOpenChange = vi.fn()
    const onSuccess = vi.fn()
    render(<CloneScanDialog scan={scan} open onOpenChange={onOpenChange} onSuccess={onSuccess} />)
    const dialog = screen.getByRole('dialog', { name: 'Clone scan configuration' })
    const name = screen.getByRole('textbox', { name: 'New scan name' })
    expect(name).toHaveValue('Weekly external (Copy)')
    expect(dialog).toHaveTextContent('1 asset group, 2 direct targets')
    expect(dialog).toHaveTextContent('externalpci')
    await userEvent.clear(name)
    await userEvent.type(name, 'Weekly copy{Enter}')
    expect(cloneIds.at(-1)).toBe('cfg-1')
    expect(cloneScan).toHaveBeenCalledTimes(1)
    expect(cloneScan).toHaveBeenCalledWith({ name: 'Weekly copy' })
    expect(onSuccess).toHaveBeenCalledWith({ id: 'cfg-2', name: 'Weekly external (Copy)' })
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('does not clone without a name, and says why with the button', async () => {
    render(<CloneScanDialog scan={scan} open onOpenChange={vi.fn()} />)
    await userEvent.clear(screen.getByRole('textbox', { name: 'New scan name' }))
    const submit = screen.getByTestId('form-dialog-submit')
    expect(submit).toBeDisabled()
    expect(submit).toHaveAccessibleDescription('Give the copy a name.')
    expect(cloneScan).not.toHaveBeenCalled()
  })
})
