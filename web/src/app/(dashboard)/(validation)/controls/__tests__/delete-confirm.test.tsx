/** Deleting a control drops its effect on priorities: its name is typed first. */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import CompensatingControlsPage from '../page'

const del = vi.hoisted(() => vi.fn())
vi.mock('swr', () => ({
  default: vi.fn(() => ({
    data: {
      data: [
        {
          id: 'c-1',
          name: 'WAF in front of billing',
          control_type: 'runtime',
          status: 'active',
          reduction_factor: 0.5,
          test_result: '',
          last_tested_at: null,
        },
      ],
      total: 1,
      page: 1,
      per_page: 100,
    },
    isLoading: false,
    mutate: vi.fn(),
  })),
}))
vi.mock('@/lib/api/client', () => ({ get: vi.fn(), post: vi.fn(), del, patch: vi.fn() }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => children,
  Permission: { CompensatingControlsWrite: 'ctem:compensating_controls:write' },
}))
vi.mock('@/features/controls/components/link-assets-dialog', () => ({
  LinkAssetsDialog: () => null,
}))

describe('Compensating controls delete', () => {
  it("is the row's one action and needs the control name typed", async () => {
    del.mockResolvedValue(undefined)
    render(<CompensatingControlsPage />)
    // The row's menu would hold one item, so the action takes the menu's place.
    expect(screen.queryByRole('button', { name: /^Actions for / })).toBeNull()
    await userEvent.click(
      await screen.findByRole('button', { name: 'Delete WAF in front of billing' })
    )
    const dialog = await screen.findByRole('alertdialog')
    const confirm = within(dialog).getByRole('button', { name: 'Delete control' })
    expect(confirm).toBeDisabled()
    await userEvent.type(within(dialog).getByRole('textbox'), 'WAF in front of billing')
    await userEvent.click(confirm)
    await waitFor(() => expect(del).toHaveBeenCalledWith('/api/v1/compensating-controls/c-1'))
  })
})
