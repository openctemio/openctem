import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const copy = vi.fn().mockResolvedValue(true)
vi.mock('@/lib/clipboard', () => ({ copyToClipboard: (...a: unknown[]) => copy(...a) }))

import {
  ProviderSetupGuide,
  ssoBackchannelLogoutUrl,
  ssoRedirectUri,
} from '@console/features/sso/components/provider-setup-guide'

describe('SSO provider setup guide', () => {
  beforeEach(() => vi.clearAllMocks())

  it('builds the addresses from the app origin', () => {
    expect(ssoRedirectUri('https://app.example.com', 'entra_id')).toBe(
      'https://app.example.com/auth/sso/callback/entra_id'
    )
    expect(ssoBackchannelLogoutUrl('https://app.example.com')).toBe(
      'https://app.example.com/api/v1/auth/backchannel-logout'
    )
  })

  it('shows the Entra redirect URI, logout URL and claims, and copies them', async () => {
    render(<ProviderSetupGuide provider="entra_id" appUrl="https://app.example.com" />)
    expect(screen.getByText('Set up in Microsoft Entra ID')).toBeInTheDocument()
    expect(screen.getByText('https://app.example.com/auth/sso/callback/entra_id')).toBeVisible()
    expect(screen.getByText('https://app.example.com/api/v1/auth/backchannel-logout')).toBeVisible()
    for (const claim of ['xms_edov', 'auth_time', 'sid']) {
      expect(screen.getByText(claim)).toBeInTheDocument()
    }
    await userEvent.click(screen.getAllByRole('button')[0])
    expect(copy).toHaveBeenCalledWith('https://app.example.com/auth/sso/callback/entra_id')
  })

  it('shows only the redirect URI for Okta and Google', () => {
    const { rerender } = render(<ProviderSetupGuide provider="okta" appUrl="https://a.example" />)
    expect(screen.getByText('https://a.example/auth/sso/callback/okta')).toBeVisible()
    expect(screen.queryByText(/backchannel-logout/)).toBeNull()
    expect(screen.queryByText('xms_edov')).toBeNull()
    rerender(<ProviderSetupGuide provider="google_workspace" appUrl="https://a.example" />)
    expect(screen.getByText('https://a.example/auth/sso/callback/google_workspace')).toBeVisible()
  })

  it('says so when the app address is unknown, without inventing one', () => {
    render(<ProviderSetupGuide provider="entra_id" appUrl="" />)
    expect(screen.getByText(/Set APP_URL on the API/)).toBeInTheDocument()
    expect(screen.queryByText(/callback\/entra_id/)).toBeNull()
  })
})
