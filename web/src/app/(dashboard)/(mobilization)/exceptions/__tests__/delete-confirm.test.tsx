/** Deleting a suppression rule asks for its name, and Delete sits after a separator. */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const triggerDelete = vi.hoisted(() => vi.fn())
vi.mock('@/features/remediation-hub/api/use-owner-names', () => ({
  useOwnerNames: () => ({ user: () => undefined }),
}))
vi.mock('@/features/exceptions', async (orig) => {
  const real = await orig<typeof import('@/features/exceptions')>()
  return {
    ...real,
    useSuppressions: () => ({
      data: {
        data: [
          {
            id: 'r-1',
            name: 'Ignore staging scanner noise',
            status: 'approved',
            requested_by: 'user-12345678',
            suppression_type: 'false_positive',
            created_at: '2026-10-01T00:00:00Z',
            updated_at: '2026-10-01T00:00:00Z',
          },
        ],
      },
      isLoading: false,
      error: undefined,
      mutate: vi.fn(),
    }),
    useApproveSuppression: () => ({ trigger: vi.fn(), isMutating: false }),
    useMarkSuppressionReviewed: () => ({ trigger: vi.fn() }),
    useRejectSuppression: () => ({ trigger: vi.fn(), isMutating: false }),
    useDeleteSuppression: () => ({ trigger: triggerDelete, isMutating: false }),
    SuppressionFormDialog: () => null,
    SuppressionDetailSheet: () => null,
    SuppressionApprovePreview: () => null,
  }
})
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  usePermissions: () => ({ can: () => true }),
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/exceptions',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
// The signed-in person's id (no profile in this test: nothing is "mine").
vi.mock('@/hooks/use-my-user-id', () => ({ useMyUserId: () => undefined }))

import ExceptionsPage from '../page'

describe('Exceptions page delete', () => {
  it('needs the rule name typed before Delete rule is enabled', async () => {
    triggerDelete.mockResolvedValue(undefined)
    render(<ExceptionsPage />)
    const menus = await screen.findAllByRole('button', { name: /^Actions for / })
    await userEvent.click(menus[0])
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Delete' }))
    const dialog = await screen.findByRole('alertdialog')
    const confirm = within(dialog).getByRole('button', { name: 'Delete rule' })
    expect(confirm).toBeDisabled()
    expect(triggerDelete).not.toHaveBeenCalled()
    await userEvent.type(within(dialog).getByRole('textbox'), 'Ignore staging scanner noise')
    await userEvent.click(confirm)
    await waitFor(() => expect(triggerDelete).toHaveBeenCalledTimes(1))
  })
})
