import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { saveEmailSettings, sendTestEmail } from '../api/use-email-settings'
import { EmailSettingsForm } from '../components/email-settings-form'

vi.mock('../api/use-email-settings', async (orig) => ({
  ...(await orig<typeof import('../api/use-email-settings')>()),
  saveEmailSettings: vi.fn(),
  sendTestEmail: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const stored = {
  enabled: true,
  host: 'smtp.example.com',
  port: 587,
  username: 'mailer',
  password_set: true,
  from: 'noreply@example.com',
  from_name: 'OpenCTEM',
  starttls: true,
  version: 3,
}

beforeEach(() => {
  vi.mocked(saveEmailSettings).mockReset().mockResolvedValue(stored)
  vi.mocked(sendTestEmail).mockReset().mockResolvedValue(undefined)
})

async function saveWithCode() {
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await userEvent.type(screen.getByLabelText('Code from your authenticator'), '123456')
  await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
}

describe('EmailSettingsForm', () => {
  it('never shows the stored password and keeps it when untouched', async () => {
    render(<EmailSettingsForm settings={stored} canEdit onSaved={() => {}} />)
    const pw = screen.getByLabelText('Password') as HTMLInputElement
    expect(pw.value).toBe('')
    expect(pw.type).toBe('password')
    expect(pw.placeholder).toMatch(/Stored/)

    await userEvent.clear(screen.getByLabelText('SMTP server'))
    await userEvent.type(screen.getByLabelText('SMTP server'), 'smtp2.example.com')
    await saveWithCode()
    await waitFor(() => expect(saveEmailSettings).toHaveBeenCalled())
    const body = vi.mocked(saveEmailSettings).mock.calls[0][0]
    expect(body).not.toHaveProperty('password')
    expect(body).toMatchObject({ host: 'smtp2.example.com', version: 3, totp_code: '123456' })
  })

  it('sends a new password, or an empty one to remove it', async () => {
    const { unmount } = render(<EmailSettingsForm settings={stored} canEdit onSaved={() => {}} />)
    await userEvent.type(screen.getByLabelText('Password'), 'n3w-pass')
    await saveWithCode()
    await waitFor(() => expect(saveEmailSettings).toHaveBeenCalled())
    expect(vi.mocked(saveEmailSettings).mock.calls[0][0]).toMatchObject({ password: 'n3w-pass' })
    unmount()

    vi.mocked(saveEmailSettings).mockClear()
    render(<EmailSettingsForm settings={stored} canEdit onSaved={() => {}} />)
    await userEvent.click(screen.getByLabelText('Remove the stored password'))
    await saveWithCode()
    await waitFor(() => expect(saveEmailSettings).toHaveBeenCalled())
    expect(vi.mocked(saveEmailSettings).mock.calls[0][0]).toMatchObject({ password: '' })
  })

  it('is read-only for an administrator who is not a super admin', () => {
    render(<EmailSettingsForm settings={stored} canEdit={false} onSaved={() => {}} />)
    expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Send a test e-mail' })).toBeNull()
    expect(screen.getByLabelText('SMTP server')).toBeDisabled()
  })

  it('sends the test e-mail', async () => {
    render(<EmailSettingsForm settings={stored} canEdit onSaved={() => {}} />)
    await userEvent.click(screen.getByRole('button', { name: 'Send a test e-mail' }))
    await waitFor(() => expect(sendTestEmail).toHaveBeenCalledTimes(1))
  })
})
