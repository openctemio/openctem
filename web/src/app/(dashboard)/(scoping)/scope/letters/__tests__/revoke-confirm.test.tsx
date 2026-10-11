import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { revokeLetter } from '@/features/scope-letters'
import ScopeLettersPage from '../page'

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/features/shared', async (orig) => ({
  ...(await orig<typeof import('@/features/shared')>()),
  GatedSectionTabs: () => null,
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
}))
vi.mock('@/features/scope-letters', async (orig) => ({
  ...(await orig<typeof import('@/features/scope-letters')>()),
  useLetters: () => ({
    data: [
      {
        id: 'l1',
        title: 'Q4 pentest authorization',
        issuer: 'Acme',
        reference: 'REF-1',
        valid_from: '2026-10-01',
        valid_until: '2026-12-31',
        in_effect: true,
        file_sha256: 'a'.repeat(64),
        created_at: '2026-10-01T00:00:00Z',
      },
    ],
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  revokeLetter: vi.fn(() => Promise.resolve({})),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('Authorization letters revoke', () => {
  it('asks before revoking and names the letter', async () => {
    render(<ScopeLettersPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Revoke' }))
    expect(revokeLetter).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Revoke the letter "Q4 pentest authorization"?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(revokeLetter).toHaveBeenCalledWith('l1'))
  })
})
