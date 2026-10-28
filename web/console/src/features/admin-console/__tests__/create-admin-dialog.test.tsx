import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { provisionAdministrator } from '../api/use-admin-users'
import { CreateAdminDialog } from '../components/create-admin-dialog'

vi.mock('../api/use-admin-users', () => ({ provisionAdministrator: vi.fn() }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const admin = { id: 'a1', email: 'bob@corp.example', name: 'Bob', role: 'readonly' }

async function submitInvitation() {
  const user = userEvent.setup()
  render(<CreateAdminDialog onCreated={vi.fn()} />)
  await user.click(screen.getByRole('button', { name: 'New administrator' }))
  await user.type(await screen.findByLabelText('Name'), 'Bob')
  await user.type(screen.getByLabelText('Email'), 'bob@corp.example')
  await user.click(screen.getByRole('button', { name: 'Send invitation' }))
}

describe('CreateAdminDialog', () => {
  beforeEach(() => vi.clearAllMocks())

  it('says the invitation was e-mailed and shows no password or link', async () => {
    vi.mocked(provisionAdministrator).mockResolvedValue({
      admin,
      invitation_emailed: true,
    } as never)
    await submitInvitation()
    expect(await screen.findByText(/An invitation was sent to this address/)).toBeInTheDocument()
    expect(screen.queryByText(/Temporary password/i)).not.toBeInTheDocument()
    expect(screen.queryByText('Invitation link')).not.toBeInTheDocument()
  })

  it('shows the link once when the platform cannot send e-mail', async () => {
    vi.mocked(provisionAdministrator).mockResolvedValue({
      admin,
      invitation_emailed: false,
      invitation_url: 'https://app.example.test/set-password#token=abc',
    } as never)
    await submitInvitation()
    expect(await screen.findByText('Invitation link')).toBeInTheDocument()
    expect(screen.getByText('https://app.example.test/set-password#token=abc')).toBeInTheDocument()
    expect(screen.getByText(/shown once/)).toBeInTheDocument()
  })

  it('says so when the invitation e-mail failed, without any link', async () => {
    vi.mocked(provisionAdministrator).mockResolvedValue({
      admin,
      invitation_emailed: false,
      invitation_failed: true,
    } as never)
    await submitInvitation()
    expect(await screen.findByText(/invitation e-mail could not be sent/)).toBeInTheDocument()
    expect(screen.queryByText('Invitation link')).not.toBeInTheDocument()
  })
})
