import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useSearchParams } from 'next/navigation'
import { toast } from 'sonner'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { SignInMethodsCard } from '../sign-in-methods-card'
import type { SignInMethods } from '../../api/use-sign-in-methods'

vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
)
vi.mock('sonner', () => ({ toast: { error: vi.fn(), success: vi.fn() } }))

const methods = vi.fn<() => { methods?: SignInMethods; isLoading: boolean; isError: boolean }>()
const mutate = vi.fn()
const link = vi.fn()
const unlink = vi.fn()
vi.mock('../../api/use-sign-in-methods', () => ({
  useSignInMethods: () => ({ ...methods(), mutate }),
  useLinkProvider: () => ({ link, linking: null }),
  useUnlinkIdentity: () => ({ unlink, isUnlinking: false }),
}))

const at = '2026-10-01T10:00:00Z'
const withParams = (q: string) =>
  vi
    .mocked(useSearchParams)
    .mockImplementation(
      () => new URLSearchParams(q) as unknown as ReturnType<typeof useSearchParams>
    )

describe('SignInMethodsCard', () => {
  beforeEach(() => vi.clearAllMocks())
  afterEach(() => withParams(''))

  it('lists the password and the offered providers, linked or not', () => {
    methods.mockReturnValue({
      methods: {
        password: true,
        identities: [{ id: 'g1', provider: 'google', created_at: at, unlinkable: true }],
        available: ['google', 'github'],
        proof: 'totp',
      },
      isLoading: false,
      isError: false,
    })
    render(<SignInMethodsCard />)
    expect(screen.getByText('Connected sign-in methods')).toBeInTheDocument()
    expect(screen.getByText('Password')).toBeInTheDocument()
    const google = screen.getByTestId('sign-in-method-google')
    expect(within(google).getByRole('button', { name: 'Unlink Google' })).toBeEnabled()
    const github = screen.getByTestId('sign-in-method-github')
    expect(within(github).getByText('Not linked')).toBeInTheDocument()
    expect(within(github).getByRole('button', { name: 'Link GitHub' })).toBeInTheDocument()
    expect(screen.queryByTestId('sign-in-method-microsoft')).not.toBeInTheDocument()
  })

  it('asks for the authenticator code before the provider round trip', async () => {
    methods.mockReturnValue({
      methods: { password: true, identities: [], available: ['google'], proof: 'totp' },
      isLoading: false,
      isError: false,
    })
    link.mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(<SignInMethodsCard />)
    await user.click(screen.getByRole('button', { name: 'Link Google' }))
    expect(link).not.toHaveBeenCalled()
    expect(screen.getByText(/Enter the code from your authenticator app/)).toBeInTheDocument()
    // No recovery codes for a sign-in method change.
    expect(screen.queryByRole('button', { name: /recovery code/i })).not.toBeInTheDocument()
    await user.type(screen.getByRole('textbox'), '123456')
    await waitFor(() => expect(link).toHaveBeenCalledWith('google', { totp: '123456' }))
  })

  it('asks a password account without two-factor for its password', async () => {
    methods.mockReturnValue({
      methods: { password: true, identities: [], available: ['google'], proof: 'password' },
      isLoading: false,
      isError: false,
    })
    link.mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(<SignInMethodsCard />)
    await user.click(screen.getByRole('button', { name: 'Link Google' }))
    await user.type(screen.getByLabelText('Password'), 'pw-1')
    await user.click(screen.getAllByRole('button', { name: 'Link' }).at(-1)!)
    expect(link).toHaveBeenCalledWith('google', { password: 'pw-1' })
  })

  it('shows a refused code in the dialog and asks again', async () => {
    methods.mockReturnValue({
      methods: { password: true, identities: [], available: ['google'], proof: 'totp' },
      isLoading: false,
      isError: false,
    })
    link.mockRejectedValue(Object.assign(new Error('x'), { code: 'LINK_PROOF_FAILED' }))
    const user = userEvent.setup()
    render(<SignInMethodsCard />)
    await user.click(screen.getByRole('button', { name: 'Link Google' }))
    await user.type(screen.getByRole('textbox'), '000000')
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The code or password is not correct.'
    )
    expect(screen.getByRole('textbox')).toHaveValue('')
  })

  it('tells an account with neither factor to turn on two-factor first', async () => {
    methods.mockReturnValue({
      methods: { password: false, identities: [], available: ['google'], proof: '' },
      isLoading: false,
      isError: false,
    })
    const user = userEvent.setup()
    render(<SignInMethodsCard />)
    await user.click(screen.getByRole('button', { name: 'Link Google' }))
    expect(
      screen.getByText(/Turn on two-factor authentication on this page first/)
    ).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(link).not.toHaveBeenCalled()
  })

  it('unlinks after confirmation and refreshes the list', async () => {
    methods.mockReturnValue({
      methods: {
        password: true,
        identities: [{ id: 'g1', provider: 'google', created_at: at, unlinkable: true }],
        available: ['google'],
        proof: 'totp',
      },
      isLoading: false,
      isError: false,
    })
    unlink.mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(<SignInMethodsCard />)
    await user.click(screen.getByRole('button', { name: 'Unlink Google' }))
    expect(unlink).not.toHaveBeenCalled()
    await user.type(screen.getByRole('textbox'), '123456')
    await waitFor(() => expect(unlink).toHaveBeenCalledWith('g1', { totp: '123456' }))
    await waitFor(() => expect(mutate).toHaveBeenCalled())
  })

  it('cannot remove the last way to sign in', () => {
    methods.mockReturnValue({
      methods: {
        password: false,
        identities: [{ id: 'g1', provider: 'google', created_at: at, unlinkable: false }],
        available: ['google'],
        proof: 'totp',
      },
      isLoading: false,
      isError: false,
    })
    render(<SignInMethodsCard />)
    expect(screen.getByRole('button', { name: 'Unlink Google' })).toBeDisabled()
    expect(
      screen.getByText('This is your only way to sign in, so it cannot be removed.')
    ).toBeInTheDocument()
  })

  it('words an API refusal of the unlink from its code', async () => {
    methods.mockReturnValue({
      methods: {
        password: false,
        identities: [
          { id: 'g1', provider: 'google', created_at: at, unlinkable: true },
          { id: 'h1', provider: 'github', created_at: at, unlinkable: true },
        ],
        available: ['google', 'github'],
        proof: 'totp',
      },
      isLoading: false,
      isError: false,
    })
    unlink.mockRejectedValue(Object.assign(new Error('x'), { code: 'LAST_SIGN_IN_METHOD' }))
    const user = userEvent.setup()
    render(<SignInMethodsCard />)
    await user.click(screen.getByRole('button', { name: 'Unlink Google' }))
    await user.type(screen.getByRole('textbox'), '123456')
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'This is your only way to sign in, so it cannot be removed.'
    )
  })

  it('shows the result of the link round trip', () => {
    methods.mockReturnValue({
      methods: { password: true, identities: [], available: ['google'], proof: 'totp' },
      isLoading: false,
      isError: false,
    })
    withParams('link_error=IDENTITY_LINKED_ELSEWHERE&provider=google')
    render(<SignInMethodsCard />)
    expect(toast.error).toHaveBeenCalledWith(
      'This provider account is already linked to another account here. Sign in with it and unlink it there first.'
    )
  })

  it('never shows text from the address', () => {
    methods.mockReturnValue({
      methods: { password: true, identities: [], available: ['google'], proof: 'totp' },
      isLoading: false,
      isError: false,
    })
    withParams('link_error=' + encodeURIComponent('Call +1 555 0100'))
    render(<SignInMethodsCard />)
    expect(toast.error).not.toHaveBeenCalled()
  })

  it('is hidden when the platform offers no social sign-in', () => {
    methods.mockReturnValue({ methods: undefined, isLoading: false, isError: true })
    const { container } = render(<SignInMethodsCard />)
    expect(container).toBeEmptyDOMElement()
  })
})
