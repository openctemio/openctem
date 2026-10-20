import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import {
  saveAlertWebhook,
  saveCaptcha,
  savePlatformAI,
  setRegion,
  useRegionSettings,
} from '../api/use-platform-settings'
import { CaptchaSettingsForm } from '../components/captcha-settings-form'
import { AlertWebhookForm } from '../components/alert-webhook-form'
import { PlatformAIForm } from '../components/platform-ai-form'
import { DeploymentRegionCard } from '../components/deployment-region-card'
import type { CaptchaSettings, PlatformAISettings, RegionSettings } from '../types'

vi.mock('../api/use-platform-settings', async (orig) => ({
  ...(await orig<typeof import('../api/use-platform-settings')>()),
  saveCaptcha: vi.fn(),
  verifyCaptchaSecret: vi.fn(),
  saveAlertWebhook: vi.fn(),
  sendTestAlert: vi.fn(),
  savePlatformAI: vi.fn(),
  testPlatformAI: vi.fn(),
  setRegion: vi.fn(),
  useRegionSettings: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn() } }))

const captcha: CaptchaSettings = {
  site_key: '0x4AAAAAAAsite',
  secret_set: true,
  source: 'console',
  locked_by_environment: false,
  env_var: 'CAPTCHA_TURNSTILE_SECRET',
  version: 2,
  changed_at: '2026-10-18T09:00:00Z',
  changed_by: 'root@example.test',
}

beforeEach(() => {
  vi.mocked(saveCaptcha).mockReset().mockResolvedValue(captcha)
  vi.mocked(saveAlertWebhook).mockReset()
  vi.mocked(savePlatformAI).mockReset()
  vi.mocked(setRegion).mockReset()
})

async function confirmWithReason(reason = 'rotate the key') {
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  const confirm = screen.getByRole('button', { name: 'Confirm' })
  expect(confirm).toBeDisabled()
  await userEvent.type(screen.getByLabelText('Reason'), reason)
  await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
}

describe('CAPTCHA settings', () => {
  it('never shows the stored secret, keeps it when untouched and sends the reason', async () => {
    render(<CaptchaSettingsForm settings={captcha} canEdit onSaved={() => {}} />)
    const secret = screen.getByLabelText('Secret key') as HTMLInputElement
    expect(secret.value).toBe('')
    expect(secret.type).toBe('password')
    expect(screen.getByText(/Changed by root@example.test/)).toBeInTheDocument()
    await userEvent.clear(screen.getByLabelText('Site key (public)'))
    await userEvent.type(screen.getByLabelText('Site key (public)'), '0x4AAAAAAAnew')
    await confirmWithReason()
    await waitFor(() => expect(saveCaptcha).toHaveBeenCalled())
    const body = vi.mocked(saveCaptcha).mock.calls[0][0]
    expect(body.secret).toBeUndefined()
    expect(body).toMatchObject({ site_key: '0x4AAAAAAAnew', reason: 'rotate the key', version: 2 })
  })

  it('is read-only and says why when the server configuration locks it', () => {
    render(
      <CaptchaSettingsForm
        settings={{ ...captcha, locked_by_environment: true }}
        canEdit
        onSaved={() => {}}
      />
    )
    expect(
      screen.getByText(/Locked by the server configuration \(CAPTCHA_TURNSTILE_SECRET\)/)
    ).toBeInTheDocument()
    expect(screen.getByLabelText('Site key (public)')).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
  })

  it('offers no change to a non-super admin', () => {
    render(<CaptchaSettingsForm settings={captcha} canEdit={false} onSaved={() => {}} />)
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
    expect(screen.getByText('Only a super admin can change this setting.')).toBeInTheDocument()
  })
})

describe('Alert webhook', () => {
  it('shows only the host and sends a new address write-only', async () => {
    vi.mocked(saveAlertWebhook).mockResolvedValue({
      enabled: true,
      url_set: true,
      url_host: 'hooks.example.com',
      secret_set: false,
      version: 1,
    })
    render(
      <AlertWebhookForm
        settings={{
          enabled: false,
          url_set: true,
          url_host: 'hooks.example.com',
          secret_set: false,
          version: 1,
        }}
        canEdit
        onSaved={() => {}}
      />
    )
    expect(screen.getByText('Receiver: hooks.example.com')).toBeInTheDocument()
    expect((screen.getByLabelText('Webhook address (https)') as HTMLInputElement).value).toBe('')
    await userEvent.type(
      screen.getByLabelText('Webhook address (https)'),
      'https://hooks.example.com/T0KEN'
    )
    await userEvent.click(screen.getByRole('switch', { name: /Send alerts to the webhook/ }))
    await confirmWithReason('page the on-call')
    await waitFor(() => expect(saveAlertWebhook).toHaveBeenCalled())
    expect(vi.mocked(saveAlertWebhook).mock.calls[0][0]).toMatchObject({
      enabled: true,
      url: 'https://hooks.example.com/T0KEN',
      reason: 'page the on-call',
    })
    expect(vi.mocked(saveAlertWebhook).mock.calls[0][0].secret).toBeUndefined()
  })
})

describe('Platform AI provider', () => {
  const ai: PlatformAISettings = {
    enabled: false,
    provider: '',
    model: '',
    base_url: '',
    allow_private: false,
    allowed_models: [],
    key_set: false,
    locked_by_environment: false,
    providers: ['claude', 'openai', 'gemini', 'openai_compatible'],
    version: 0,
  }
  it('is off by default and cannot be turned on without a model and key', async () => {
    render(<PlatformAIForm settings={ai} canEdit onSaved={() => {}} />)
    await userEvent.click(screen.getByRole('switch', { name: /Offer platform AI/ }))
    expect(screen.getByText(/Choose a provider and a model and set its key/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    await userEvent.type(screen.getByLabelText('Model'), 'claude-sonnet-4')
    await userEvent.type(screen.getByLabelText('API key'), 'sk-test-key-123456')
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled()
  })

  it('an OpenAI-compatible server needs a base URL and no key; the private toggle is shown only for it', async () => {
    const compat = { ...ai, provider: 'openai_compatible' }
    render(<PlatformAIForm settings={compat} canEdit onSaved={() => {}} />)
    expect(screen.getByRole('switch', { name: /Allow private addresses/ })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('switch', { name: /Offer platform AI/ }))
    await userEvent.type(screen.getByLabelText('Model'), 'llama3')
    expect(screen.getByText(/Choose a model and a base URL/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    await userEvent.type(screen.getByLabelText('Base URL'), 'http://10.0.0.5:11434/v1')
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled()
  })

  it('has no private toggle for a hosted provider', () => {
    render(<PlatformAIForm settings={{ ...ai, provider: 'claude' }} canEdit onSaved={() => {}} />)
    expect(
      screen.queryByRole('switch', { name: /Allow private addresses/ })
    ).not.toBeInTheDocument()
  })
})

describe('Deployment region', () => {
  const base: RegionSettings = {
    region: '',
    source: 'none',
    locked_by_environment: false,
    env_var: 'DEPLOYMENT_REGION',
    settable: true,
  }
  const mockRegion = (r: RegionSettings) =>
    vi
      .mocked(useRegionSettings)
      .mockReturnValue({ data: r, isLoading: false, mutate: vi.fn() } as never)

  it('can be set once before the first organization, with a reason', async () => {
    mockRegion(base)
    vi.mocked(setRegion).mockResolvedValue({ ...base, region: 'eu-central', settable: false })
    render(<DeploymentRegionCard canEdit />)
    await userEvent.type(screen.getByLabelText('Region name'), 'eu-central')
    await userEvent.click(screen.getByRole('button', { name: 'Set the region' }))
    await userEvent.type(screen.getByLabelText('Reason'), 'EU data residency')
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() =>
      expect(setRegion).toHaveBeenCalledWith({ region: 'eu-central', reason: 'EU data residency' })
    )
  })

  it('cannot be set once organizations exist or a region is fixed', () => {
    mockRegion({ ...base, settable: false })
    const { unmount } = render(<DeploymentRegionCard canEdit />)
    expect(screen.getByText(/Organizations already exist/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Set the region' })).not.toBeInTheDocument()
    unmount()
    mockRegion({ ...base, region: 'eu-central', source: 'console', settable: false })
    render(<DeploymentRegionCard canEdit />)
    expect(screen.getByText('eu-central')).toBeInTheDocument()
    expect(screen.getByText(/it cannot be changed/)).toBeInTheDocument()
  })
})
