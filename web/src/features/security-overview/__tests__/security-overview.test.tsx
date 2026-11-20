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

const row = (id: string) => document.getElementById(`check-${id}`) as HTMLElement

describe('SecurityOverview', () => {
  beforeEach(() => vi.clearAllMocks())

  it('renders the score, the counts, and every open check with a status word', async () => {
    fetcher.mockResolvedValue(RESPONSE)
    render(withSWR(<SecurityOverview />))
    expect(await screen.findByTestId('security-score')).toHaveTextContent('72')
    expect(screen.getByRole('heading', { level: 1, name: 'Security overview' })).toBeInTheDocument()
    expect(
      screen.getByRole('progressbar', { name: 'Security score: 72 out of 100' })
    ).toBeInTheDocument()
    expect(screen.getByTestId('count-risk')).toHaveTextContent('1')
    expect(screen.getByTestId('count-warn')).toHaveTextContent('2')
    expect(screen.getByTestId('count-pass')).toHaveTextContent('2')
    expect(screen.getByText(/^Checked /)).toBeInTheDocument()

    // Group titles come from the dictionary, not the server; a group whose
    // checks all passed has no section of its own.
    for (const g of ['Sign-in', 'People and access', 'Credentials']) {
      expect(screen.getByRole('heading', { level: 2, name: g })).toBeInTheDocument()
    }
    expect(screen.queryByRole('heading', { name: 'Organization' })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Scanning' })).not.toBeInTheDocument()

    const risk = row('sign_in.admins_without_mfa')
    expect(within(risk).getByText('Owners and admins without two-factor')).toBeInTheDocument()
    // Status is text, never colour only; the count is in the sentence.
    expect(within(risk).getByText('Risk')).toBeInTheDocument()
    expect(
      within(risk).getByText(/2 owners or admins sign in with a password alone/)
    ).toBeInTheDocument()
    expect(
      within(risk).getByRole('link', { name: 'Review: Owners and admins without two-factor' })
    ).toHaveAttribute('href', '/settings/members')

    expect(within(row('sign_in.ip_allowlist')).getByText('Info')).toBeInTheDocument()
    expect(within(row('people.dormant_members')).getByText('Warning')).toBeInTheDocument()
  })

  it('folds the passed checks and shows them on demand, without a link', async () => {
    fetcher.mockResolvedValue(RESPONSE)
    const user = userEvent.setup()
    render(withSWR(<SecurityOverview />))
    await screen.findByTestId('security-score')
    expect(row('sign_in.mfa_admins_required')).toBeNull()
    const toggle = screen.getByRole('button', { name: 'Show the 2 passed checks' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    await user.click(toggle)
    expect(screen.getByRole('button', { name: 'Hide the 2 passed checks' })).toHaveAttribute(
      'aria-expanded',
      'true'
    )
    const pass = row('sign_in.mfa_admins_required')
    expect(within(pass).getByText('Passed')).toBeInTheDocument()
    expect(within(pass).queryByRole('link')).not.toBeInTheDocument()
  })

  it('lists the worst checks of a group first', async () => {
    fetcher.mockResolvedValue(RESPONSE)
    render(withSWR(<SecurityOverview />))
    await screen.findByTestId('security-score')
    const ids = Array.from(document.querySelectorAll('[id^="check-sign_in."]')).map((el) => el.id)
    expect(ids).toEqual(['check-sign_in.admins_without_mfa', 'check-sign_in.ip_allowlist'])
  })

  it('shows the page frame with loading rows first', () => {
    fetcher.mockReturnValue(new Promise(() => {}))
    render(withSWR(<SecurityOverview />))
    expect(screen.getByRole('heading', { level: 1, name: 'Security overview' })).toBeInTheDocument()
    expect(screen.getByLabelText('Loading Security overview')).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByRole('button', { name: 'Re-check' })).toBeDisabled()
  })

  it('shows an error state, distinct from an empty overview, with a retry', async () => {
    fetcher.mockRejectedValueOnce(new Error('boom'))
    const user = userEvent.setup()
    render(withSWR(<SecurityOverview />))
    expect(await screen.findByText("Couldn't load Security overview")).toBeInTheDocument()
    expect(screen.queryByTestId('security-score')).not.toBeInTheDocument()
    fetcher.mockResolvedValueOnce(RESPONSE)
    await user.click(screen.getByRole('button', { name: 'Retry' }))
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
    // A moved settings page: its new home, the #setting kept.
    expect(safeInternalLink('/settings/authentication#ip-allowlist')).toBe(
      '/settings/sign-in#ip-allowlist'
    )
    expect(safeInternalLink('/settings/domains')).toBe('/settings/sign-in?tab=domains')
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
