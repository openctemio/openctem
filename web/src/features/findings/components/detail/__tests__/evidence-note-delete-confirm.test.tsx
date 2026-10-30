/** Deleting an evidence note asks for its text (or short id) before it is sent. */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const deleteEvidence = vi.fn()
vi.mock('../../../api/use-finding-evidence', async (orig) => ({
  ...(await orig<typeof import('../../../api/use-finding-evidence')>()),
  useFindingEvidenceNotes: () => ({
    data: {
      data: [
        {
          id: 'n-1',
          kind: 'note',
          description: 'Screenshot of the admin login',
          created_at: '2026-10-20T10:00:00Z',
        },
      ],
      total: 1,
    },
    isLoading: false,
    mutate: vi.fn(),
  }),
  useAddFindingEvidence: () => ({ trigger: vi.fn(), isMutating: false }),
  useDeleteFindingEvidence: () => ({ trigger: deleteEvidence, isMutating: false }),
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { ManualEvidenceNotesSection } from '../manual-evidence-notes'

describe('ManualEvidenceNotesSection delete', () => {
  it('needs the note text typed before Delete note is enabled', async () => {
    render(<ManualEvidenceNotesSection findingId="f-1" />)
    await userEvent.click(screen.getByRole('button', { name: 'Delete evidence note' }))
    const dialog = await screen.findByRole('alertdialog')
    const button = within(dialog).getByRole('button', { name: 'Delete note' })
    expect(button).toBeDisabled()
    expect(deleteEvidence).not.toHaveBeenCalled()
    await userEvent.type(within(dialog).getByRole('textbox'), 'Screenshot of the admin login')
    expect(button).toBeEnabled()
    await userEvent.click(button)
    await waitFor(() => expect(deleteEvidence).toHaveBeenCalled())
  })
})
