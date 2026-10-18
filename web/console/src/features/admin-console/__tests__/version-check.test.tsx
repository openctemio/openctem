/**
 * Console version check (RFC-105): the banner on every console page and
 * System > Software updates. Security releases always show; an update notice
 * can be hidden per version; links render only for our own pages; only a
 * super admin sees the offline import.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { VersionCheckStatus } from '../types'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const state = vi.hoisted(() => ({ data: undefined as VersionCheckStatus | undefined }))
const importReleaseFeed = vi.hoisted(() => vi.fn())
const setVersionCheckEnabled = vi.hoisted(() => vi.fn())
vi.mock('../api/use-version-check', () => ({
  useVersionCheck: () => ({ data: state.data }),
  importReleaseFeed,
  setVersionCheckEnabled,
}))

const { VersionCheckBanner } = await import('../components/version-check-banner')
const { SoftwareUpdatesPanel, releaseLink, MAX_RELEASE_FEED_BYTES } =
  await import('../components/software-updates-panel')

function status(patch: Partial<VersionCheckStatus> = {}): VersionCheckStatus {
  return {
    enabled: true,
    configured: true,
    feed_url:
      'https://github.com/openctemio/openctem/releases/latest/download/openctem-releases.json',
    source: 'online',
    running: 'v0.9.7',
    comparable: true,
    latest: 'v0.9.8',
    update_available: true,
    newer: [
      {
        version: 'v0.9.8',
        published_at: '2026-10-15T10:00:00Z',
        notes_url: 'https://github.com/openctemio/openctem/releases/tag/v0.9.8',
      },
    ],
    advisories: [],
    stale: false,
    ...patch,
  }
}

const advisory = {
  id: 'OCTEM-2026-0001',
  severity: 'critical' as const,
  title: 'Session fixation in the console',
  fixed_in: 'v0.9.8',
  published_at: '2026-10-15T10:00:00Z',
  url: 'https://openctem.io/security/OCTEM-2026-0001',
}

beforeEach(() => {
  state.data = undefined
  importReleaseFeed.mockReset()
  toast.success.mockReset()
  toast.error.mockReset()
  window.localStorage.clear()
})

describe('releaseLink', () => {
  it('keeps only https links to our own pages', () => {
    expect(releaseLink('https://openctem.io/security/x')).toBe('https://openctem.io/security/x')
    expect(releaseLink('https://github.com/openctemio/openctem/releases/tag/v1.0.0')).toBeDefined()
    for (const bad of [
      'https://example.com/download',
      'http://openctem.io/x',
      'https://openctem.io.example.com/',
      'https://user@openctem.io/',
      'https://openctem.io:8443/',
      'https://github.com/someone/openctem/releases',
      'javascript:alert(1)',
      'not a url',
      undefined,
    ]) {
      expect(releaseLink(bad)).toBeUndefined()
    }
  })
})

describe('VersionCheckBanner', () => {
  it('shows nothing without information, for a build without a version, or when up to date', () => {
    const { container, rerender } = render(<VersionCheckBanner />)
    expect(container).toBeEmptyDOMElement()
    state.data = status({ comparable: false })
    rerender(<VersionCheckBanner />)
    expect(container).toBeEmptyDOMElement()
    state.data = status({ update_available: false, newer: [], latest: 'v0.9.7' })
    rerender(<VersionCheckBanner />)
    expect(container).toBeEmptyDOMElement()
  })

  it('always shows a security release, with no way to hide it', () => {
    state.data = status({ advisories: [advisory], severity: 'critical', fixed_in: 'v0.9.8' })
    render(<VersionCheckBanner />)
    expect(screen.getByTestId('version-check-security')).toBeInTheDocument()
    expect(screen.getByText('Security release: upgrade to v0.9.8')).toBeInTheDocument()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'See the advisories' })).toHaveAttribute(
      'href',
      '/system/software-updates'
    )
  })

  it('hides an update notice for that version only', async () => {
    const user = userEvent.setup()
    state.data = status()
    const { rerender } = render(<VersionCheckBanner />)
    expect(screen.getByText('OpenCTEM v0.9.8 is available')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Hide until the next release' }))
    expect(screen.queryByTestId('version-check-update')).not.toBeInTheDocument()
    state.data = status({ latest: 'v0.9.9' })
    rerender(<VersionCheckBanner />)
    expect(screen.getByText('OpenCTEM v0.9.9 is available')).toBeInTheDocument()
  })
})

describe('SoftwareUpdatesPanel', () => {
  it('lists the advisories and newer releases, links only to our pages, no import for others', () => {
    render(
      <SoftwareUpdatesPanel
        status={status({
          advisories: [
            advisory,
            { ...advisory, id: 'X-2', title: 'Foreign link', url: 'https://example.com/x' },
          ],
          severity: 'critical',
          fixed_in: 'v0.9.8',
        })}
        canImport={false}
        onChanged={vi.fn()}
      />
    )
    expect(screen.getByText('Security release available')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Session fixation in the console' })).toHaveAttribute(
      'href',
      advisory.url
    )
    expect(screen.queryByRole('link', { name: 'Foreign link' })).not.toBeInTheDocument()
    expect(screen.getByText('Foreign link')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'v0.9.8' })).toBeInTheDocument()
    expect(screen.queryByText('Import release information')).not.toBeInTheDocument()
  })

  it('says when the build cannot verify, when the information is old, and why the last check failed', () => {
    render(
      <SoftwareUpdatesPanel
        status={status({
          configured: false,
          stale: true,
          feed_expires_at: '2026-09-01T00:00:00Z',
          last_error: 'unreachable',
        })}
        canImport
        onChanged={vi.fn()}
      />
    )
    expect(screen.getByText('Release checks are not active in this build')).toBeInTheDocument()
    expect(screen.getByText('The release information is out of date')).toBeInTheDocument()
  })

  it('imports the chosen file as read and refuses an oversized one locally', async () => {
    const user = userEvent.setup()
    const onChanged = vi.fn()
    importReleaseFeed.mockResolvedValue(status())
    render(<SoftwareUpdatesPanel status={status()} canImport onChanged={onChanged} />)
    const input = screen.getByLabelText('Release feed file (JSON, up to 256 KiB)')
    const feed = { schema: 'openctem.io/release-bundle/v1', keyset: {}, feed: {} }
    await user.upload(
      input,
      new File([JSON.stringify(feed)], 'openctem-releases.json', { type: 'application/json' })
    )
    await user.click(screen.getByRole('button', { name: 'Import' }))
    await waitFor(() => expect(importReleaseFeed).toHaveBeenCalledWith(feed))
    expect(onChanged).toHaveBeenCalled()

    importReleaseFeed.mockReset()
    const big = new File(['x'.repeat(MAX_RELEASE_FEED_BYTES + 1)], 'big.json', {
      type: 'application/json',
    })
    await user.upload(input, big)
    await user.click(screen.getByRole('button', { name: 'Import' }))
    await waitFor(() => expect(toast.error).toHaveBeenCalled())
    expect(importReleaseFeed).not.toHaveBeenCalled()
  })
})

describe('daily online check switch', () => {
  beforeEach(() => vi.clearAllMocks())

  it('a super admin turns the check off without a restart', async () => {
    setVersionCheckEnabled.mockResolvedValueOnce(status({ enabled: false }))
    const changed = vi.fn()
    render(<SoftwareUpdatesPanel status={status()} canImport onChanged={changed} />)
    await userEvent.setup().click(screen.getByRole('switch', { name: 'Daily online check' }))
    expect(setVersionCheckEnabled).toHaveBeenCalledWith(false)
    await waitFor(() => expect(changed).toHaveBeenCalled())
  })

  it('no switch when VERSION_CHECK_ENABLED=false locks it, and the reason is shown', () => {
    render(
      <SoftwareUpdatesPanel
        status={status({ enabled: false, locked_by_environment: true })}
        canImport
        onChanged={vi.fn()}
      />
    )
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
    expect(screen.getByText(/locked by the server configuration/)).toBeInTheDocument()
  })

  it('no switch for an administrator who cannot change it', () => {
    render(<SoftwareUpdatesPanel status={status()} canImport={false} onChanged={vi.fn()} />)
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
  })
})
