import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

let data: unknown
vi.mock('../api/use-security-overview', () => ({ useSecurityOverview: () => ({ data }) }))

import { SettingsAttention } from '../components/settings-attention'

describe('SettingsAttention', () => {
  it('renders nothing for someone who cannot read the overview', () => {
    data = { score: 50, counts: { risk: 1, warn: 0 }, checks: [] }
    const { container } = render(<SettingsAttention enabled={false} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the score and the first things to fix, risks first, linking to their setting', () => {
    data = {
      score: 72,
      counts: { risk: 1, warn: 2, pass: 5, info: 1 },
      checks: [
        {
          id: 'sign_in.email_verification',
          group: 'sign_in',
          status: 'warn',
          link: '/settings/authentication#email-verification',
        },
        {
          id: 'sign_in.admins_without_mfa',
          group: 'sign_in',
          status: 'risk',
          count: 1,
          link: '/settings/members',
        },
        {
          id: 'organization.verified_domain',
          group: 'organization',
          status: 'info',
          link: '/settings/domains',
        },
        {
          id: 'credentials.api_keys_unused',
          group: 'credentials',
          status: 'warn',
          count: 2,
          link: '//evil.example',
        },
      ],
    }
    render(<SettingsAttention enabled />)
    expect(screen.getByRole('heading', { level: 2, name: 'Needs attention' })).toBeInTheDocument()
    expect(screen.getByLabelText(/72 out of 100/)).toHaveTextContent('Security score 72 / 100')
    const rows = Array.from(document.querySelectorAll('[data-slot="settings-row"]'))
    expect(rows).toHaveLength(3)
    expect(rows[0]).toHaveTextContent('Risk')
    // The fix link names its check, so three "Open the setting" links differ for a screen reader.
    expect(screen.getAllByRole('link', { name: /^Open the setting: / })).toHaveLength(2)
    expect(screen.getAllByRole('link').map((a) => a.getAttribute('href'))).not.toContain(
      '//evil.example'
    )
    expect(screen.getByRole('link', { name: /open the security overview/i })).toHaveAttribute(
      'href',
      '/settings/security'
    )
  })

  it('says so when nothing needs attention', () => {
    data = { score: 100, counts: { risk: 0, warn: 0 }, checks: [] }
    render(<SettingsAttention enabled />)
    expect(screen.getByText('Nothing needs attention right now.')).toBeInTheDocument()
  })
})
