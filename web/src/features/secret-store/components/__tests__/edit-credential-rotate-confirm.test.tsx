import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { SecretStoreCredential } from '@/lib/api/secret-store-types'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const rotate = vi.hoisted(() => vi.fn())
const update = vi.hoisted(() => vi.fn())
vi.mock('@/lib/api/secret-store-hooks', () => ({
  useRotateSecretStoreCredential: () => ({ trigger: rotate, isMutating: false }),
  useUpdateSecretStoreCredential: () => ({ trigger: update, isMutating: false }),
  invalidateSecretStoreCache: vi.fn(async () => undefined),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }))

import { EditCredentialDialog } from '../edit-credential-dialog'

const credential = {
  id: 'c1',
  name: 'github-token',
  credential_type: 'api_key',
  key_version: 1,
  encryption_algorithm: 'aes-256-gcm',
} as unknown as SecretStoreCredential

describe('EditCredentialDialog rotation', () => {
  beforeEach(() => {
    rotate.mockReset().mockResolvedValue({})
    update.mockReset().mockResolvedValue({})
  })

  it('asks before a new secret replaces the stored one', async () => {
    const user = userEvent.setup()
    render(<EditCredentialDialog open onOpenChange={vi.fn()} credential={credential} />)
    await user.type(screen.getByPlaceholderText('Enter new API key to update'), 'new-secret-value')
    await user.click(screen.getByRole('button', { name: 'Save Changes' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Rotate the secret of "github-token"?')
    expect(rotate).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Rotate secret' }))
    await waitFor(() =>
      expect(rotate).toHaveBeenCalledWith({ api_key: { key: 'new-secret-value' } })
    )
  })

  it('Cancel rotates nothing', async () => {
    const user = userEvent.setup()
    render(<EditCredentialDialog open onOpenChange={vi.fn()} credential={credential} />)
    await user.type(screen.getByPlaceholderText('Enter new API key to update'), 'new-secret-value')
    await user.click(screen.getByRole('button', { name: 'Save Changes' }))
    await user.click(await screen.findByRole('button', { name: 'Cancel' }))
    expect(rotate).not.toHaveBeenCalled()
  })

  it('a metadata-only edit saves without the rotation question', async () => {
    const user = userEvent.setup()
    render(<EditCredentialDialog open onOpenChange={vi.fn()} credential={credential} />)
    const name = screen.getByDisplayValue('github-token')
    await user.clear(name)
    await user.type(name, 'github-token-2')
    await user.click(screen.getByRole('button', { name: 'Save Changes' }))
    await waitFor(() => expect(update).toHaveBeenCalledWith({ name: 'github-token-2' }))
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    expect(rotate).not.toHaveBeenCalled()
  })
})
