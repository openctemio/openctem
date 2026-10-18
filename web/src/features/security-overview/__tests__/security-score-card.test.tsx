import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

let data: unknown
vi.mock('../api/use-security-overview', () => ({ useSecurityOverview: () => ({ data }) }))

import { SecurityScoreCard } from '../components/security-score-card'

describe('SecurityScoreCard', () => {
  it('renders nothing for someone who cannot read the overview', () => {
    data = { score: 50, counts: { risk: 1, warn: 0 }, checks: [] }
    const { container } = render(<SecurityScoreCard enabled={false} />)
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
    render(<SecurityScoreCard enabled />)
    expect(screen.getByText('72')).toBeInTheDocument()
    expect(screen.getByRole('progressbar', { name: /72 out of 100/ })).toBeInTheDocument()
    const items = screen.getAllByRole('listitem')
    expect(items).toHaveLength(3)
    expect(items[0]).toHaveTextContent('Risk')
    expect(screen.getAllByRole('link').map((a) => a.getAttribute('href'))).not.toContain(
      '//evil.example'
    )
    expect(screen.getByRole('link', { name: /open the security overview/i })).toHaveAttribute(
      'href',
      '/settings/security'
    )
  })
})
