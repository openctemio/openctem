import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import {
  saveVulnFeedSources,
  testVulnFeedSources,
  useVulnFeedSources,
} from '../api/use-platform-settings'
import { useFeedRelay } from '../api/use-feed-relay'
import { VulnFeedSourcesCard } from '../components/vulnfeed-sources-card'
import type { VulnFeedSourcesSettings } from '../types'

vi.mock('../api/use-platform-settings', async (orig) => ({
  ...(await orig<typeof import('../api/use-platform-settings')>()),
  useVulnFeedSources: vi.fn(),
  saveVulnFeedSources: vi.fn(),
  testVulnFeedSources: vi.fn(),
}))
vi.mock('../api/use-feed-relay', async (orig) => ({
  ...(await orig<typeof import('../api/use-feed-relay')>()),
  useFeedRelay: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn() } }))
vi.mock('../components/role-required-notice', () => ({
  RoleRequiredNotice: () => <p>role required</p>,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const base: VulnFeedSourcesSettings = {
  base_url: 'https://github.com/openctemio/vulnfeed-bundles/releases',
  mirrors: ['https://mirror.example.com/vulnfeed'],
  default_base_url: 'https://github.com/openctemio/vulnfeed-bundles/releases',
  default_mirrors: [],
  source: 'console',
  locked_by_environment: false,
  env_vars: ['VULNFEED_BASE_URL', 'VULNFEED_MIRRORS'],
  max_mirrors: 5,
  root_official: true,
  root_key_id: 'SHA256:cb88',
  bundle_dir_set: false,
  version: 3,
}

function mockData(settings: VulnFeedSourcesSettings, mode: 'direct' | 'relay' = 'direct') {
  vi.mocked(useVulnFeedSources).mockReturnValue({
    data: settings,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  } as unknown as ReturnType<typeof useVulnFeedSources>)
  vi.mocked(useFeedRelay).mockReturnValue({
    data: { mode },
  } as unknown as ReturnType<typeof useFeedRelay>)
}

beforeEach(() => {
  vi.mocked(saveVulnFeedSources).mockReset().mockResolvedValue(base)
  vi.mocked(testVulnFeedSources).mockReset()
})

describe('vulnerability feed address', () => {
  it('shows the root and the bundle folder read only', () => {
    mockData(base)
    render(<VulnFeedSourcesCard canEdit />)
    expect(screen.getByTestId('feed-root')).toHaveTextContent('Official root')
    expect(screen.getByTestId('feed-root')).toHaveTextContent('SHA256:cb88')
    expect(screen.getByTestId('feed-bundle-dir')).toHaveTextContent('Set on the server: no')
    expect(screen.queryByDisplayValue('SHA256:cb88')).not.toBeInTheDocument()
  })

  it('names a custom root without offering to change it', () => {
    mockData({ ...base, root_official: false, bundle_dir_set: true })
    render(<VulnFeedSourcesCard canEdit />)
    expect(screen.getByTestId('feed-root')).toHaveTextContent('Custom root (set on the server)')
    expect(screen.getByTestId('feed-bundle-dir')).toHaveTextContent('Set on the server: yes')
    expect(screen.getByTestId('feed-sources-bundle-dir')).toBeInTheDocument()
  })

  it('saves the addresses with the version and a reason', async () => {
    mockData(base)
    render(<VulnFeedSourcesCard canEdit />)
    await userEvent.click(screen.getByRole('button', { name: 'Add mirror' }))
    await userEvent.type(screen.getByLabelText('Mirror 2'), 'https://second.example.com/feed')
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    const dialog = screen.getByRole('alertdialog')
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'company mirror')
    const buttons = within(dialog).getAllByRole('button')
    await userEvent.click(buttons[buttons.length - 1])
    expect(saveVulnFeedSources).toHaveBeenCalledWith({
      base_url: base.base_url,
      mirrors: ['https://mirror.example.com/vulnfeed', 'https://second.example.com/feed'],
      reason: 'company mirror',
      version: 3,
    })
  })

  it('is locked while the server environment sets the address', () => {
    mockData({ ...base, locked_by_environment: true, source: 'environment' })
    render(<VulnFeedSourcesCard canEdit />)
    expect(screen.getByText(/Locked by the server configuration/)).toBeInTheDocument()
    expect(screen.getByDisplayValue(base.base_url)).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Add mirror' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument()
  })

  it('in relay mode marks the mirrors direct only and turns the test off', () => {
    mockData(base, 'relay')
    render(<VulnFeedSourcesCard canEdit />)
    expect(screen.getByText(/Used in direct mode only/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Test fetch' })).toBeDisabled()
    expect(screen.getByText('Relay')).toBeInTheDocument()
  })

  it('shows each address with its test outcome', async () => {
    mockData(base)
    vi.mocked(testVulnFeedSources).mockResolvedValue({
      results: [
        { origin: base.base_url, ok: true, format: 'v2', sequence: 41 },
        { origin: base.mirrors[0], ok: false, error: 'root_mismatch' },
      ],
    })
    render(<VulnFeedSourcesCard canEdit />)
    await userEvent.click(screen.getByRole('button', { name: 'Test fetch' }))
    expect(testVulnFeedSources).toHaveBeenCalledWith({
      base_url: base.base_url,
      mirrors: base.mirrors,
    })
    const list = await screen.findByTestId('feed-test-results')
    expect(list).toHaveTextContent('Release 41, signed by the trusted root.')
    expect(list).toHaveTextContent('not signed by the root this server trusts')
  })

  it('an administrator without the permission reads only', () => {
    mockData(base)
    render(<VulnFeedSourcesCard canEdit={false} />)
    expect(screen.getByText('role required')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Test fetch' })).not.toBeInTheDocument()
    expect(screen.getByDisplayValue(base.base_url)).toBeDisabled()
  })
})
