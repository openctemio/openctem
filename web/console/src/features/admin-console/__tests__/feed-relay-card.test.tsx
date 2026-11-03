import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { FeedRelayCard, alertLabel, staleReasonText } from '../components/feed-relay-card'
import type { FeedRelayStatus } from '../api/use-feed-relay'

const mocks = vi.hoisted(() => ({
  status: { current: null as FeedRelayStatus | null },
  save: vi.fn(),
  mutate: vi.fn(),
  success: vi.fn(),
  error: vi.fn(),
}))

vi.mock('sonner', () => ({ toast: { success: mocks.success, error: mocks.error } }))
vi.mock('../api/use-feed-relay', async (orig) => ({
  ...(await orig<typeof import('../api/use-feed-relay')>()),
  useFeedRelay: () => ({
    data: mocks.status.current,
    error: undefined,
    isLoading: false,
    mutate: mocks.mutate,
  }),
  saveFeedRelay: mocks.save,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const t = (_k: string, fallback: string, vars?: Record<string, string | number>) =>
  fallback.replace(/\{(\w+)\}/g, (_, n) => String(vars?.[n] ?? ''))

function status(patch: Partial<FeedRelayStatus> = {}): FeedRelayStatus {
  return {
    mode: 'direct',
    version: 3,
    sensor_ids: [],
    sensors: [],
    feeds: [],
    not_relayed: [],
    candidates: [
      { id: 's1', name: 'edge-1', status: 'active', eligible: true },
      { id: 's2', name: 'edge-2', status: 'active', eligible: true },
      { id: 's3', name: 'edge-3', status: 'active', eligible: true },
      { id: 's4', name: 'edge-4', status: 'active', eligible: true },
      { id: 's5', name: 'scanner-old', status: 'active', eligible: false, reason: 'no_capability' },
      { id: 's6', name: 'parked', status: 'disabled', eligible: false, reason: 'inactive' },
    ],
    alerts: [],
    ...patch,
  }
}

const relaying = (patch: Partial<FeedRelayStatus> = {}) =>
  status({
    mode: 'relay',
    sensor_ids: ['s1'],
    sensors: [
      {
        id: 's1',
        name: 'edge-1',
        can_relay: true,
        online: false,
        bytes_today: 2048,
        last_served_at: '2026-11-02T08:00:00Z',
      },
    ],
    feeds: [
      {
        feed: 'vulnfeed',
        age_seconds: 50 * 3600,
        stale_reason: 'relay_offline',
        last_import: {
          phase: 'imported',
          status: 'done',
          files: 0,
          delivered: 0,
          bytes_delivered: 0,
          bytes_wanted: 0,
          created_at: '2026-10-31T08:00:00Z',
        },
        current: {
          phase: 'chunks',
          status: 'open',
          files: 12,
          delivered: 5,
          bytes_delivered: 1024,
          bytes_wanted: 4096,
          claimed_by: 's1',
          created_at: '2026-11-02T09:00:00Z',
        },
      },
    ],
    alerts: [{ key: 'relay_offline', since: '2026-11-02T09:00:00Z' }],
    ...patch,
  })

describe('FeedRelayCard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.save.mockResolvedValue({})
  })

  it('offers only eligible platform sensors, explains the others and caps the pick at three', async () => {
    mocks.status.current = status()
    render(<FeedRelayCard canEdit />)
    await userEvent.click(screen.getByLabelText(/relay: platform sensors bring the feeds/i))
    for (const name of ['edge-1', 'edge-2', 'edge-3', 'edge-4']) {
      expect(screen.getByLabelText(name)).toBeInTheDocument()
    }
    expect(screen.queryByLabelText('scanner-old')).toBeNull()
    const why = screen.getByTestId('feed-relay-ineligible')
    expect(why).toHaveTextContent('scanner-old (cannot relay)')
    expect(why).toHaveTextContent('parked (not active)')
    expect(why).toHaveTextContent(/SENSOR_FEED_RELAY=0/)

    const save = screen.getByRole('button', { name: 'Save' })
    expect(save).toBeDisabled() // relay needs at least one sensor
    await userEvent.click(screen.getByLabelText('edge-1'))
    await userEvent.click(screen.getByLabelText('edge-2'))
    await userEvent.click(screen.getByLabelText('edge-3'))
    expect(screen.getByLabelText('edge-4')).toBeDisabled()
    expect(save).toBeEnabled()

    await userEvent.click(save)
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText(/never falls back to direct/i)).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(mocks.save).toHaveBeenCalledWith({
        mode: 'relay',
        sensor_ids: ['s1', 's2', 's3'],
        expected_version: 3,
      })
    )
  })

  it('shows the relay status: alerts, age, round progress, claimer, the stale reason with its fix and relay stats', () => {
    mocks.status.current = relaying()
    render(<FeedRelayCard canEdit={false} />)
    expect(screen.getByRole('alert')).toHaveTextContent('No relay sensor online for over an hour')
    expect(screen.getByText('50 hours')).toBeInTheDocument()
    expect(
      screen.getByText(/Downloading data files: 5 of 12 files, 1\.0 KiB received/)
    ).toBeInTheDocument()
    const feed = document.querySelector('[data-feed="vulnfeed"]') as HTMLElement
    expect(within(feed).getByText('edge-1')).toBeInTheDocument()
    expect(within(feed).getByText(/has been seen for 10 minutes/)).toBeInTheDocument()
    expect(within(feed).getByText(/start or reconnect a relay sensor/i)).toBeInTheDocument()
    expect(document.querySelector('[data-sensor="s1"]')).toHaveTextContent(
      /Offline.*in the last 24 hours/
    )
    // Read-only administrators get no actions.
    expect(screen.queryByRole('button', { name: /switch to direct/i })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
  })

  it('switching to direct is an explicit, confirmed action', async () => {
    mocks.status.current = relaying()
    render(<FeedRelayCard canEdit />)
    await userEvent.click(screen.getByRole('button', { name: /switch to direct now/i }))
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText(/outbound requests/i)).toBeInTheDocument()
    expect(mocks.save).not.toHaveBeenCalled()
    await userEvent.click(within(dialog).getByRole('button', { name: /switch to direct now/i }))
    await waitFor(() =>
      expect(mocks.save).toHaveBeenCalledWith({
        mode: 'direct',
        sensor_ids: [],
        expected_version: 3,
      })
    )
    expect(mocks.success).toHaveBeenCalledWith(expect.stringMatching(/directly/i))
  })

  it('points to the offline bundle guide in relay mode', () => {
    mocks.status.current = relaying()
    render(<FeedRelayCard canEdit />)
    expect(screen.getByRole('link', { name: /offline bundle guide/i })).toHaveAttribute(
      'href',
      'https://docs.openctem.io/airgap/feeds/'
    )
  })

  it('says why relay mode is locked instead of offering it', () => {
    mocks.status.current = status({ locked: 'bundle_dir' })
    render(<FeedRelayCard canEdit />)
    expect(screen.getByText(/VULNFEED_BUNDLE_DIR/)).toBeInTheDocument()
    expect(screen.queryByRole('radiogroup')).toBeNull()
  })

  it('names every stale reason and alert in plain words', () => {
    for (const code of [
      'no_relay_designated',
      'relay_offline',
      'signer_refused',
      'sensor_refused',
      'upstream_missing',
      'nothing_delivered',
      'pin_mismatch',
      'verify_failed',
      'rollback_refused',
      'plan_failed',
      'import_failed',
      'round_expired',
      'spool_full',
    ]) {
      const r = staleReasonText(code, t)
      expect(r.message).not.toBe('The last relay cycle failed.')
      expect(r.fix.length).toBeGreaterThan(10)
    }
    expect(alertLabel('round_failed:vulnfeed:verify_failed', t)).toMatch(
      /^Vulnerability feed: .*did not verify/
    )
    expect(alertLabel('feed_stale:vulnfeed', t)).toBe('Vulnerability feed is out of date')
  })
})
