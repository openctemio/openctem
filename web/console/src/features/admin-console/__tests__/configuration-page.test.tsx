import { describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ConfigurationItem } from '../types'

const items: ConfigurationItem[] = [
  {
    key: 'signup_policy',
    group: 'sign_in',
    managed: 'console',
    source: 'console',
    env_var: 'SIGNUP_MODE',
    ceiling: true,
    restart_required: false,
    page: '/system/sign-up',
    changed_at: '2026-10-18T09:00:00Z',
    changed_by: 'root@example.test',
  },
  {
    key: 'captcha.turnstile',
    group: 'sign_in',
    managed: 'console',
    source: 'environment',
    env_var: 'CAPTCHA_TURNSTILE_SECRET',
    locked_by: 'CAPTCHA_TURNSTILE_SECRET',
    restart_required: false,
    page: '/system/captcha',
  },
  {
    key: 'ADMIN_AUDIT_SINK',
    group: 'audit',
    managed: 'server',
    source: 'environment',
    env_var: 'ADMIN_AUDIT_SINK',
    secret: true,
    is_set: true,
    restart_required: true,
  },
  {
    key: 'APP_URL',
    group: 'instance',
    managed: 'server',
    source: 'environment',
    env_var: 'APP_URL',
    value: 'https://ctem.example.test',
    restart_required: true,
  },
]
vi.mock('../api/use-configuration', () => ({
  useConfiguration: () => ({ data: { data: items }, isLoading: false, mutate: vi.fn() }),
}))
vi.mock('../api/use-platform-settings', () => ({
  useRegionSettings: () => ({
    data: {
      region: 'eu-central',
      source: 'console',
      locked_by_environment: false,
      env_var: 'DEPLOYMENT_REGION',
      settable: false,
    },
    isLoading: false,
    mutate: vi.fn(),
  }),
}))
vi.mock('../components/admin-console-shell', () => ({ useAdmin: () => ({ role: 'readonly' }) }))

const { default: ConfigurationPage } =
  await import('@console/app/(console)/system/configuration/page')

describe('Configuration page', () => {
  it('shows where each setting comes from, with secrets only as set or not set', () => {
    render(<ConfigurationPage />)
    expect(screen.getByText('Sign-up policy')).toBeInTheDocument()
    expect(screen.getByText(/changed by root@example.test/)).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: /Change/ })[0]).toHaveAttribute(
      'href',
      '/system/sign-up'
    )
    const sink = screen.getByText('Admin audit stream').closest('div')!.parentElement!
    expect(within(sink).getByText('Set')).toBeInTheDocument()
    expect(screen.getByText('https://ctem.example.test')).toBeInTheDocument()
    // The deployment region card sits on this page.
    expect(screen.getByText('eu-central')).toBeInTheDocument()
  })

  it('marks a console setting the server configuration locks', () => {
    render(<ConfigurationPage />)
    expect(screen.getByText('Locked by the server')).toBeInTheDocument()
    expect(
      screen.getByText(/locked by the server configuration \(CAPTCHA_TURNSTILE_SECRET\)/)
    ).toBeInTheDocument()
  })

  it('filters to the settings that need a restart', async () => {
    render(<ConfigurationPage />)
    await userEvent.setup().click(screen.getByRole('tab', { name: 'Needs a restart' }))
    expect(screen.queryByText('Sign-up policy')).not.toBeInTheDocument()
    expect(screen.getByText('Public address')).toBeInTheDocument()
  })
})
