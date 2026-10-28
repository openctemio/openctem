import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { saveSocialProvider, testSocialProvider } from '../api/use-platform-settings'
import { SocialLoginSettingsForm } from '../components/social-login-settings-form'
import type { SocialLoginSettings, SocialProvider } from '../types'

vi.mock('../api/use-platform-settings', async (orig) => ({
  ...(await orig<typeof import('../api/use-platform-settings')>()),
  saveSocialProvider: vi.fn(),
  testSocialProvider: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn() } }))

const provider = (
  p: SocialProvider['provider'],
  over: Partial<SocialProvider> = {}
): SocialProvider => ({
  provider: p,
  enabled: false,
  client_id: '',
  secret_set: false,
  scopes: [],
  default_scopes: ['openid', 'email'],
  source: 'none',
  locked_by_environment: false,
  env_var: `OAUTH_${p.toUpperCase()}_CLIENT_SECRET`,
  active: false,
  undecryptable: false,
  redirect_uri: `https://ctem.example.com/auth/callback/${p}`,
  ...over,
})

const settings = (over: Partial<SocialLoginSettings> = {}): SocialLoginSettings => ({
  providers: [provider('google'), provider('github'), provider('microsoft')],
  master_enabled: true,
  javascript_origin: 'https://ctem.example.com',
  signup_accounts: 'closed',
  version: 3,
  ...over,
})

beforeEach(() => {
  vi.mocked(saveSocialProvider).mockReset().mockResolvedValue(settings())
  vi.mocked(testSocialProvider).mockReset().mockResolvedValue({ result: 'valid' })
})

describe('Social login settings', () => {
  it('shows the exact redirect URI of each provider and the JavaScript origin of Google', () => {
    render(<SocialLoginSettingsForm settings={settings()} canEdit onSaved={() => {}} />)
    const google = within(screen.getByTestId('social-google'))
    expect(
      google.getByDisplayValue('https://ctem.example.com/auth/callback/google')
    ).toBeInTheDocument()
    expect(google.getByDisplayValue('https://ctem.example.com')).toBeInTheDocument()
    expect(
      within(screen.getByTestId('social-microsoft')).getByDisplayValue(
        'https://ctem.example.com/auth/callback/microsoft'
      )
    ).toBeInTheDocument()
    expect(
      within(screen.getByTestId('social-github')).queryByLabelText('Authorized JavaScript origin')
    ).toBeNull()
  })

  it('never shows the stored secret, keeps it when untouched and sends the reason', async () => {
    const s = settings({
      providers: [
        provider('google', {
          client_id: 'g-id.apps.example',
          secret_set: true,
          enabled: true,
          active: true,
        }),
        provider('github'),
        provider('microsoft'),
      ],
    })
    render(<SocialLoginSettingsForm settings={s} canEdit onSaved={() => {}} />)
    const card = within(screen.getByTestId('social-google'))
    const secret = card.getByLabelText('Client secret') as HTMLInputElement
    expect(secret.value).toBe('')
    expect(secret.type).toBe('password')
    await userEvent.click(card.getByLabelText('Offer on the sign-in page'))
    await userEvent.click(card.getByRole('button', { name: 'Save' }))
    const dialog = within(screen.getByRole('alertdialog'))
    await userEvent.type(dialog.getByLabelText('Reason'), 'pause for maintenance')
    const buttons = dialog.getAllByRole('button')
    await userEvent.click(buttons[buttons.length - 1])
    await waitFor(() => expect(saveSocialProvider).toHaveBeenCalled())
    const [name, body] = vi.mocked(saveSocialProvider).mock.calls[0]
    expect(name).toBe('google')
    expect(body.secret).toBeUndefined()
    expect(body).toMatchObject({
      enabled: false,
      client_id: 'g-id.apps.example',
      reason: 'pause for maintenance',
      version: 3,
    })
  })

  it('states who can sign in when a provider is turned on while sign-up is closed', async () => {
    render(<SocialLoginSettingsForm settings={settings()} canEdit onSaved={() => {}} />)
    const card = within(screen.getByTestId('social-github'))
    await userEvent.click(card.getByLabelText('Offer on the sign-in page'))
    expect(card.getByText(/Public sign-up is closed/)).toBeInTheDocument()
  })

  it('tests the configuration without showing the secret', async () => {
    render(<SocialLoginSettingsForm settings={settings()} canEdit onSaved={() => {}} />)
    const card = within(screen.getByTestId('social-github'))
    expect(card.getByRole('button', { name: 'Test configuration' })).toBeDisabled()
    await userEvent.type(card.getByLabelText('Client ID'), 'Iv1.abcdef123456')
    await userEvent.type(card.getByLabelText('Client secret'), 'candidate-secret-123')
    await userEvent.click(card.getByRole('button', { name: 'Test configuration' }))
    await waitFor(() =>
      expect(testSocialProvider).toHaveBeenCalledWith('github', {
        client_id: 'Iv1.abcdef123456',
        secret: 'candidate-secret-123',
      })
    )
  })

  it('is read-only and says why when the server environment sets the provider', () => {
    const s = settings({
      providers: [
        provider('google'),
        provider('github', {
          locked_by_environment: true,
          source: 'environment',
          secret_set: true,
          active: true,
          enabled: true,
        }),
        provider('microsoft'),
      ],
    })
    render(<SocialLoginSettingsForm settings={s} canEdit onSaved={() => {}} />)
    const card = within(screen.getByTestId('social-github'))
    expect(card.getByText('Set by the server environment')).toBeInTheDocument()
    expect(
      card.getByText(/Locked by the server configuration \(OAUTH_GITHUB_CLIENT_SECRET\)/)
    ).toBeInTheDocument()
    expect(card.getByLabelText('Client ID')).toBeDisabled()
    expect(card.queryByRole('button', { name: 'Save' })).toBeNull()
    expect(
      within(screen.getByTestId('social-google')).getByRole('button', { name: 'Save' })
    ).toBeInTheDocument()
  })

  it('is read-only for an administrator who is not a super admin', () => {
    render(<SocialLoginSettingsForm settings={settings()} canEdit={false} onSaved={() => {}} />)
    expect(screen.getAllByText('Only a super admin can change this setting.')).toHaveLength(3)
    expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
  })
})
