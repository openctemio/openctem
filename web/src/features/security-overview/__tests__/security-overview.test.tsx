import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'

const fetcher = vi.fn()
vi.mock('@/lib/api/client', () => ({ fetcher: (url: string) => fetcher(url) }))

import { en, vi as viDict } from '@/lib/i18n/dictionaries'

import { SecurityOverview } from '../components/security-overview'
import {
  CHECK_GROUPS,
  CHECK_STATUSES,
  groupChecks,
  normalizeChecks,
  safeInternalLink,
} from '../lib/checks'

function withSWR(ui: React.ReactNode) {
  return <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>
}

const RESPONSE = {
  generated_at: '2026-10-18T10:00:00Z',
  score: 72,
  counts: { risk: 1, warn: 2, pass: 2, info: 1 },
  checks: [
    {
      id: 'sign_in.mfa_admins_required',
      group: 'sign_in',
      status: 'pass',
      link: '/settings/authentication',
    },
    {
      id: 'sign_in.admins_without_mfa',
      group: 'sign_in',
      status: 'risk',
      count: 2,
      link: '/settings/members',
    },
    {
      id: 'sign_in.ip_allowlist',
      group: 'sign_in',
      status: 'info',
      link: '/settings/authentication',
    },
    {
      id: 'people.dormant_members',
      group: 'people',
      status: 'warn',
      count: 3,
      link: '/settings/members',
    },
    {
      id: 'credentials.api_keys_expiring',
      group: 'credentials',
      status: 'warn',
      count: 1,
      link: '/settings/api-keys',
    },
    {
      id: 'organization.verified_domain',
      group: 'organization',
      status: 'pass',
      count: 1,
      link: '/settings/domains',
    },
  ],
}

describe('SecurityOverview', () => {
  beforeEach(() => vi.clearAllMocks())

  it('renders the score, the counts, and every check with a status word', async () => {
    fetcher.mockResolvedValue(RESPONSE)
    render(withSWR(<SecurityOverview />))
    expect(await screen.findByTestId('security-score')).toHaveTextContent('72')
    // Accessible label on the progress bar.
    expect(
      screen.getByRole('progressbar', { name: 'Security score: 72 out of 100' })
    ).toBeInTheDocument()
    expect(screen.getByTestId('count-risk')).toHaveTextContent('1')
    expect(screen.getByTestId('count-warn')).toHaveTextContent('2')
    expect(screen.getByTestId('count-pass')).toHaveTextContent('2')

    // Group titles come from the dictionary, not the server.
    for (const g of ['Sign-in', 'People and access', 'Credentials', 'Organization']) {
      expect(screen.getByText(g)).toBeInTheDocument()
    }
    expect(screen.queryByText('Scanning')).not.toBeInTheDocument()

    const risk = screen.getByTestId('check-sign_in.admins_without_mfa')
    expect(within(risk).getByText('Owners and admins without two-factor')).toBeInTheDocument()
    // Status is text, never colour only; the count is in the sentence.
    expect(within(risk).getByText('Risk')).toBeInTheDocument()
    expect(
      within(risk).getByText(/2 owners or admins sign in with a password alone/)
    ).toBeInTheDocument()
    expect(within(risk).getByRole('link', { name: 'Review' })).toHaveAttribute(
      'href',
      '/settings/members'
    )

    const pass = screen.getByTestId('check-sign_in.mfa_admins_required')
    expect(within(pass).getByText('Passed')).toBeInTheDocument()
    expect(within(pass).queryByRole('link')).not.toBeInTheDocument()
    expect(
      within(screen.getByTestId('check-sign_in.ip_allowlist')).getByText('Info')
    ).toBeInTheDocument()
    expect(
      within(screen.getByTestId('check-people.dormant_members')).getByText('Warning')
    ).toBeInTheDocument()
  })

  it('lists the worst checks of a group first', async () => {
    fetcher.mockResolvedValue(RESPONSE)
    render(withSWR(<SecurityOverview />))
    await screen.findByTestId('security-score')
    const ids = screen
      .getAllByTestId(/^check-sign_in\./)
      .map((el) => el.getAttribute('data-testid'))
    expect(ids).toEqual([
      'check-sign_in.admins_without_mfa',
      'check-sign_in.ip_allowlist',
      'check-sign_in.mfa_admins_required',
    ])
  })

  it('shows a loading skeleton first', () => {
    fetcher.mockReturnValue(new Promise(() => {}))
    render(withSWR(<SecurityOverview />))
    expect(screen.getByTestId('security-overview-loading')).toBeInTheDocument()
  })

  it('shows an error state, distinct from an empty overview, with a retry', async () => {
    fetcher.mockRejectedValueOnce(new Error('boom'))
    const user = userEvent.setup()
    render(withSWR(<SecurityOverview />))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Could not load the security overview'
    )
    expect(screen.queryByTestId('security-score')).not.toBeInTheDocument()
    fetcher.mockResolvedValueOnce(RESPONSE)
    await user.click(screen.getByRole('button', { name: 'Try again' }))
    expect(await screen.findByTestId('security-score')).toHaveTextContent('72')
  })

  it('Re-check fetches again', async () => {
    fetcher.mockResolvedValue(RESPONSE)
    const user = userEvent.setup()
    render(withSWR(<SecurityOverview />))
    await screen.findByTestId('security-score')
    expect(fetcher).toHaveBeenCalledTimes(1)
    fetcher.mockResolvedValue({ ...RESPONSE, score: 90 })
    await user.click(screen.getByRole('button', { name: 'Re-check' }))
    await screen.findByText('90')
    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it('does not link off-site paths from the API', () => {
    expect(safeInternalLink('/settings/members')).toBe('/settings/members')
    expect(safeInternalLink('https://example.com/x')).toBeNull()
    expect(safeInternalLink('//example.com')).toBeNull()
    expect(safeInternalLink('')).toBeNull()
  })
})

describe('check helpers', () => {
  it('drops malformed checks and keeps unknown groups last', () => {
    const checks = normalizeChecks([
      { id: 'a', group: 'future_group', status: 'warn' },
      { id: 'people.join_requests', group: 'people', status: 'pass' },
      { group: 'people', status: 'warn' },
      { id: 'b', group: 'people', status: 'bogus' },
    ])
    expect(checks.map((c) => c.id)).toEqual(['a', 'people.join_requests'])
    expect(groupChecks(checks).map(([g]) => g)).toEqual(['people', 'future_group'])
  })
})

describe('security overview dictionaries', () => {
  it('has en and vi text for every group, check title and per-status explanation', () => {
    for (const dict of [en, viDict] as Record<string, string>[]) {
      for (const g of CHECK_GROUPS) {
        expect(dict[`securityOverview.group.${g}`], g).toBeTruthy()
      }
      for (const [id, statuses] of Object.entries(CHECK_STATUSES)) {
        expect(dict[`securityOverview.check.${id}.title`], id).toBeTruthy()
        for (const st of statuses) {
          expect(dict[`securityOverview.check.${id}.desc.${st}`], `${id}.${st}`).toBeTruthy()
        }
      }
      for (const st of ['risk', 'warn', 'pass', 'info']) {
        expect(dict[`securityOverview.status.${st}`], st).toBeTruthy()
      }
    }
  })

  it('covers every check the API can return (13)', () => {
    expect(Object.keys(CHECK_STATUSES)).toHaveLength(13)
  })
})
