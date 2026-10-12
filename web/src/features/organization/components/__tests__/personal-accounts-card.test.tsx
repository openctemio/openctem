import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('../../api/use-members', () => ({
  useMembers: () => ({
    members: [
      { id: 'm1', user_id: 'u1', name: 'Vendor Vu', email: 'vu@vendor.example', role: 'member' },
    ],
  }),
}))

import { PersonalAccountsCard } from '../personal-accounts-card'

const props = {
  tenantSlug: 'acme',
  policy: 'allowed_with_mfa' as const,
  onPolicyChange: vi.fn(),
  exceptions: [],
  onExceptionsChange: vi.fn(),
  ssoEnforced: false,
}

describe('PersonalAccountsCard', () => {
  it('changes the policy', async () => {
    const onPolicyChange = vi.fn()
    render(<PersonalAccountsCard {...props} onPolicyChange={onPolicyChange} />)
    await userEvent.setup().click(screen.getByLabelText('Blocked'))
    expect(onPolicyChange).toHaveBeenCalledWith('blocked')
  })

  it('hides SSO exceptions unless SSO is enforced', () => {
    render(<PersonalAccountsCard {...props} />)
    expect(screen.queryByText('SSO exceptions')).toBeNull()
  })

  it('adds and removes an SSO exception', async () => {
    const user = userEvent.setup()
    const onExceptionsChange = vi.fn()
    const { rerender } = render(
      <PersonalAccountsCard {...props} ssoEnforced onExceptionsChange={onExceptionsChange} />
    )
    await user.type(screen.getByLabelText('Member'), 'vu')
    await user.click(screen.getByRole('button', { name: /Vendor Vu/ }))
    await user.type(screen.getByLabelText('Reason'), 'No account at our IdP')
    await user.click(screen.getByRole('button', { name: /Add exception/ }))
    const added = onExceptionsChange.mock.calls[0][0]
    expect(added).toHaveLength(1)
    expect(added[0]).toMatchObject({ user_id: 'u1', reason: 'No account at our IdP' })
    expect(added[0].expires_at).toMatch(/T23:59:59Z$/)

    const remove = vi.fn()
    rerender(
      <PersonalAccountsCard {...props} ssoEnforced exceptions={added} onExceptionsChange={remove} />
    )
    await user.click(screen.getByRole('button', { name: /Remove the exception of Vendor Vu/ }))
    expect(remove).toHaveBeenCalledWith([])
  })

  it('is read-only when the caller cannot change security settings', () => {
    render(<PersonalAccountsCard {...props} ssoEnforced disabled />)
    expect(screen.queryByRole('button', { name: /Add exception/ })).toBeNull()
  })
})
