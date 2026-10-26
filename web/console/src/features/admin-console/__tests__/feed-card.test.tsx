import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { FeedCard } from '../components/feed-card'
import { BundleDetail } from '../components/bundle-detail'
import { feedProblem, formatSpan, shortKeyId } from '../lib/feed-status'
import type { ThreatIntelFeed } from '../types'

const t = (_k: string, fallback: string, params?: Record<string, string | number>) =>
  fallback.replace(/\{(\w+)\}/g, (_m, k: string) => String(params?.[k] ?? ''))

function feed(patch: Partial<ThreatIntelFeed>): ThreatIntelFeed {
  return {
    source: 'kev',
    enabled: true,
    state: 'up_to_date',
    catalog_records: 1512,
    records_changed: 0,
    interval_seconds: 3600,
    stale_after_seconds: 21600,
    ...patch,
  }
}

describe('feedProblem', () => {
  it('maps each code to a message and an action, with its parameters', () => {
    const p = feedProblem(
      feed({
        state: 'failing',
        error_code: 'http_status',
        error_params: { host: 'www.cisa.gov', status: '403' },
      }),
      t
    )
    expect(p?.message).toBe('www.cisa.gov answered 403.')
    expect(p?.action).toMatch(/blocks this network/)
    expect(
      feedProblem(
        feed({
          state: 'refused',
          error_code: 'guard_refused',
          error_params: { kind: 'snapshot', count: '10', limit: '90' },
        }),
        t
      )?.message
    ).toBe('Refused: the snapshot has 10 entries, below the minimum of 90.')
  })

  it('shows nothing for a feed that is fine or running', () => {
    expect(feedProblem(feed({}), t)).toBeNull()
    expect(feedProblem(feed({ state: 'running', error_code: 'failed' }), t)).toBeNull()
  })

  it('formats spans and key ids', () => {
    expect(formatSpan(1200, t)).toBe('20 min')
    expect(formatSpan(21600, t)).toBe('6 h')
    expect(formatSpan(259200, t)).toBe('3 d')
    expect(
      shortKeyId('SHA256:cb881872776e9b00fa699ccdc809af71243728279083f7bcdf6dd171e5a246c2')
    ).toBe('SHA256:cb88187...a246c2')
  })
})

vi.mock('@/context/i18n-provider', () => ({ useTranslation: () => ({ t }) }))

describe('FeedCard', () => {
  it('shows both sizes, last attempt and last success separately, and the next run', () => {
    render(
      <FeedCard
        feed={feed({
          records_changed: 3,
          last_attempt_at: new Date(Date.now() - 60_000).toISOString(),
          next_run_at: new Date(Date.now() + 3_600_000).toISOString(),
        })}
        canWrite
        busy={false}
        onSync={() => {}}
        onToggle={() => {}}
      />
    )
    expect(screen.getByText('In the catalog')).toBeInTheDocument()
    expect(screen.getByText('1,512')).toBeInTheDocument()
    expect(screen.getByText('Changed in the last run')).toBeInTheDocument()
    expect(screen.getByText('Last attempt')).toBeInTheDocument()
    expect(screen.getByText('Last success')).toBeInTheDocument()
    expect(screen.getByText('Next run')).toBeInTheDocument()
    expect(screen.getByText('Up to date')).toBeInTheDocument()
  })

  it('a running feed disables Sync now', () => {
    render(
      <FeedCard
        feed={feed({ state: 'running' })}
        canWrite
        busy={false}
        onSync={() => {}}
        onToggle={() => {}}
      />
    )
    expect(screen.getByRole('button', { name: 'Running' })).toBeDisabled()
  })
})

describe('BundleDetail', () => {
  it('shows sequence, signature and per-source freshness', () => {
    const d = {
      applied_sequence: 1482,
      keyset_version: 1,
      root_key_id: 'SHA256:cb881872776e9b00fa699ccdc809af71243728279083f7bcdf6dd171e5a246c2',
      bundle_created_at: new Date().toISOString(),
      sources: [
        { name: 'nvd', as_of: new Date().toISOString(), fresh: true },
        { name: 'epss', as_of: '2026-01-01T00:00:00Z', fresh: false },
      ],
    }
    render(<BundleDetail feed={feed({ source: 'vulnfeed', detail: d })} />)
    expect(screen.getByText('1482')).toBeInTheDocument()
    expect(screen.getByText(/Verified \(key set v1, root SHA256:cb88187/)).toBeInTheDocument()
    expect(screen.getByText('Fresh')).toBeInTheDocument()
    expect(screen.getByText('Stale')).toBeInTheDocument()
  })

  it('does not claim a signature before any bundle was applied', () => {
    render(
      <BundleDetail
        feed={feed({
          source: 'vulnfeed',
          detail: { applied_sequence: 0, keyset_version: 0, sources: [] },
        })}
      />
    )
    expect(screen.getByText('Nothing to verify yet')).toBeInTheDocument()
  })
})
