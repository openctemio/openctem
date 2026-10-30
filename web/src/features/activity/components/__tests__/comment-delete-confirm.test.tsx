/** Deleting a comment removes it for everyone: the typed text gates the button. */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CommentCard } from '../activity-items'
import type { ActivityCommentItem } from '../../types'

const item = {
  kind: 'comment',
  id: 'c-12345678-aaaa',
  at: '2026-10-20T10:00:00Z',
  actor: { name: 'Ada', id: 'u1' },
  body: 'Looks fixed',
} as unknown as ActivityCommentItem

async function openDelete(onDelete: () => void, body = item) {
  render(<CommentCard item={body} onDelete={onDelete} />)
  await userEvent.click(screen.getByRole('button', { name: 'Comment actions' }))
  await userEvent.click(await screen.findByRole('menuitem', { name: 'Delete' }))
  return await screen.findByRole('alertdialog')
}

describe('CommentCard delete', () => {
  it('keeps Delete disabled until the comment text is typed', async () => {
    const onDelete = vi.fn()
    const dialog = await openDelete(onDelete)
    const button = within(dialog).getByRole('button', { name: 'Delete comment' })
    expect(button).toBeDisabled()
    await userEvent.type(within(dialog).getByRole('textbox'), 'Looks fixed')
    expect(button).toBeEnabled()
    await userEvent.click(button)
    await waitFor(() => expect(onDelete).toHaveBeenCalledTimes(1))
  })

  it('asks for the short id when the comment is too long to retype', async () => {
    const onDelete = vi.fn()
    const dialog = await openDelete(onDelete, { ...item, body: 'x'.repeat(100) })
    expect(dialog).toHaveTextContent('c-123456')
    expect(onDelete).not.toHaveBeenCalled()
  })
})
