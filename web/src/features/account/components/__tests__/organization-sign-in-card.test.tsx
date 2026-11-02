import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { OrganizationSignInCard } from '../organization-sign-in-card'
import type { SSOLinks } from '../../api/use-sso-links'

vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
)
vi.mock('sonner', () => ({ toast: { error: vi.fn(), success: vi.fn() } }))

const state = vi.fn<() => { links?: SSOLinks; isLoading: boolean; isError: boolean }>()
const mutate = vi.fn()
const link = vi.fn()
const unlink = vi.fn()
vi.mock('../../api/use-sso-links', () => ({
  useSSOLinks: () => ({ ...state(), mutate }),
  useStartSSOLink: () => ({ link, linking: null }),
  useUnlinkSSOIdentity: () => ({ unlink, isUnlinking: false }),
}))

const at = '2026-10-01T10:00:00Z'
const acme = {
  org_slug: 'acme',
  org_name: 'Acme',
  provider: 'entra_id' as const,
  display_name: 'Microsoft Entra ID',
}

describe('OrganizationSignInCard', () => {
  beforeEach(() => vi.clearAllMocks())

  it('is hidden when no organization has single sign-on', () => {
    state.mockReturnValue({
      links: { organizations: [], other: [], proof: 'totp' },
      isLoading: false,
      isError: false,
    })
    const { container } = render(<OrganizationSignInCard />)
    expect(container).toBeEmptyDOMElement()
  })

  it('asks for the authenticator code before going to the identity provider', async () => {
    state.mockReturnValue({
      links: { organizations: [acme], other: [], proof: 'totp' },
      isLoading: false,
      isError: false,
    })
    link.mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(<OrganizationSignInCard />)
    const row = screen.getByTestId('organization-sign-in-acme-entra_id')
    expect(within(row).getByText('Not linked')).toBeInTheDocument()
    await user.click(within(row).getByRole('button', { name: 'Link Acme' }))
    expect(link).not.toHaveBeenCalled()
    await user.type(screen.getByRole('textbox'), '123456')
    await waitFor(() => expect(link).toHaveBeenCalledWith(acme, { totp: '123456' }))
  })

  it('unlinks a linked organization after the proof and refreshes', async () => {
    state.mockReturnValue({
      links: {
        organizations: [{ ...acme, identity: { id: 'i1', created_at: at, unlinkable: true } }],
        other: [],
        proof: 'password',
      },
      isLoading: false,
      isError: false,
    })
    unlink.mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(<OrganizationSignInCard />)
    await user.click(screen.getByRole('button', { name: 'Unlink Acme' }))
    await user.type(screen.getByLabelText('Password'), 'pw-1')
    await user.click(screen.getAllByRole('button', { name: 'Unlink' }).at(-1)!)
    await waitFor(() => expect(unlink).toHaveBeenCalledWith('i1', { password: 'pw-1' }))
    expect(mutate).toHaveBeenCalled()
  })

  it('keeps an identity of an account without a password managed by the organization', () => {
    state.mockReturnValue({
      links: {
        organizations: [{ ...acme, identity: { id: 'i1', created_at: at, unlinkable: false } }],
        other: [],
        proof: 'totp',
      },
      isLoading: false,
      isError: false,
    })
    render(<OrganizationSignInCard />)
    expect(screen.getByText('Managed by your organization')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Unlink Acme' })).toBeDisabled()
  })
})
