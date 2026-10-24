import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { TooltipProvider } from '@/components/ui/tooltip'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const api = vi.hoisted(() => ({ del: vi.fn() }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('../api/use-scan-windows', () => ({
  deleteScanWindowPolicy: (...a: unknown[]) => api.del(...a),
  invalidateScanWindows: vi.fn(async () => undefined),
  useScanWindowPolicies: () => ({
    data: {
      data: [
        {
          id: 'p1',
          name: 'Change freeze',
          kind: 'blackout',
          enabled: true,
          open_now: true,
          timezone: 'UTC',
          min_tier: 'standard',
          selector: {},
          slots: [],
          one_offs: [],
        },
      ],
    },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
}))
vi.mock('../api/use-selector-options', () => ({ useSelectorOptions: () => ({ names: {} }) }))
vi.mock('../components/overrides-section', () => ({ OverridesSection: () => null }))
vi.mock('../components/policy-dialog', () => ({ PolicyDialog: () => null }))

import { ScanWindowsPanel } from '../components/scan-windows-panel'

describe('ScanWindowsPanel delete', () => {
  beforeEach(() => api.del.mockReset().mockResolvedValue(undefined))

  it('deletes a policy only after its name is typed', async () => {
    const user = userEvent.setup()
    render(
      <TooltipProvider>
        <ScanWindowsPanel />
      </TooltipProvider>
    )
    await user.click(screen.getByRole('button', { name: 'Delete Change freeze' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete the window policy "Change freeze"?')
    const confirm = within(dialog).getByRole('button', { name: 'Delete policy' })
    expect(confirm).toBeDisabled()
    expect(api.del).not.toHaveBeenCalled()
    await user.type(within(dialog).getByRole('textbox'), 'Change freeze')
    await user.click(confirm)
    await waitFor(() => expect(api.del).toHaveBeenCalledWith('p1'))
  })
})
