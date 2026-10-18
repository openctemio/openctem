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
    key: 'CAPTCHA_TURNSTILE_SECRET',
    group: 'sign_in',
    managed: 'server',
    source: 'environment',
    env_var: 'CAPTCHA_TURNSTILE_SECRET',
    secret: true,
    is_set: true,
    restart_required: true,
    planned: true,
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

const { default: ConfigurationPage } = await import('@console/app/(console)/system/configuration/page')

describe('Configuration page', () => {
  it('shows where each setting comes from, with secrets only as set or not set', () => {
    render(<ConfigurationPage />)
    expect(screen.getByText('Sign-up policy')).toBeInTheDocument()
    expect(screen.getByText(/changed by root@example.test/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Change/ })).toHaveAttribute('href', '/system/sign-up')
    const turnstile = screen.getByText('CAPTCHA (Turnstile) keys').closest('div')!.parentElement!
    expect(within(turnstile).getByText('Set')).toBeInTheDocument()
    expect(screen.getByText('https://ctem.example.test')).toBeInTheDocument()
  })

  it('filters to the settings that need a restart', async () => {
    render(<ConfigurationPage />)
    await userEvent.setup().click(screen.getByRole('tab', { name: 'Needs a restart' }))
    expect(screen.queryByText('Sign-up policy')).not.toBeInTheDocument()
    expect(screen.getByText('Public address')).toBeInTheDocument()
  })
})
