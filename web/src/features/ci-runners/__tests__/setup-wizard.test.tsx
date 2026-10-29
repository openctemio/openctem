import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CISetupEntry } from '../components/ci-setup-wizard'
import { CITrustRefusals } from '../components/ci-refusals'

const mockSave = vi.fn()
let runs: unknown[] = []
let refusals: unknown[] = []
let apps: unknown = { data: [{ provider: 'github', account_login: 'acme' }] }
let trusts: unknown[] = []
type RunsCall = [{ provider?: string }, { enabled?: boolean; refreshInterval?: number }]
const runsCalls: RunsCall[] = []

vi.mock('../api/use-ci', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../api/use-ci')>()),
  useSaveTrustConfig: () => ({ trigger: mockSave, isMutating: false }),
  useSCMApps: () => ({ data: apps }),
  useTrustConfigs: () => ({ data: { data: trusts } }),
  useCIRuns: (f: RunsCall[0], o: RunsCall[1]) => {
    runsCalls.push([f, o])
    return { data: { data: runs } }
  },
  useTrustRefusals: (o: { enabled?: boolean }) => ({
    data: o?.enabled === false ? undefined : { data: refusals },
    isLoading: false,
    mutate: vi.fn(),
  }),
}))

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't-123', slug: 'acme', role: 'owner' } }),
}))

async function throughToWaiting() {
  render(<CISetupEntry canWrite />)
  await userEvent.click(screen.getByRole('button', { name: /connect a pipeline/i }))
  const dialog = screen.getByRole('dialog')
  // Step 1: GitHub Actions is the default choice.
  expect(within(dialog).getByRole('radio', { name: 'GitHub Actions' })).toHaveAttribute(
    'aria-checked',
    'true'
  )
  await userEvent.click(within(dialog).getByRole('button', { name: /next/i }))
  // Step 2: the GitHub App installation is offered as an owner.
  const create = within(dialog).getByRole('button', { name: /create trust/i })
  expect(create).toBeDisabled()
  await userEvent.click(within(dialog).getByRole('button', { name: 'acme' }))
  expect(within(dialog).getByLabelText(/organizations or owners/i)).toHaveValue('acme')
  await userEvent.click(create)
  await waitFor(() => expect(mockSave).toHaveBeenCalled())
  const body = mockSave.mock.calls[0][0].body
  expect(body.provider).toBe('github')
  expect(body.rules.owners).toEqual(['acme'])
  expect(body.rules.allow_fork_pull_requests).toBe(false)
  // Step 3: the snippet names the organization's tenant.
  expect(await within(dialog).findByTestId('ci-setup-snippet')).toHaveTextContent('t-123')
  await userEvent.click(within(dialog).getByRole('button', { name: /wait for the first run/i }))
  return dialog
}

describe('Connect a pipeline', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    runs = []
    refusals = []
    runsCalls.length = 0
    apps = { data: [{ provider: 'github', account_login: 'acme' }] }
    trusts = []
    mockSave.mockResolvedValue({
      id: 'trust-1',
      provider: 'github',
      audience: 'openctem:tenant:t-123',
    })
  })

  it('creates the trust, shows the snippet and waits for the first run', async () => {
    const dialog = await throughToWaiting()
    expect(within(dialog).getByText(/waiting for the first run/i)).toBeInTheDocument()
    // The waiting step polls the provider's runs.
    expect(
      runsCalls.some(
        ([f, o]) => f.provider === 'github' && o.enabled && (o.refreshInterval ?? 0) > 0
      )
    ).toBe(true)
  })

  it('says when the first run arrived and links to it', async () => {
    runs = [{ id: 'run-9', trust_config_id: 'trust-1', repository: 'github.com/acme/api' }]
    const dialog = await throughToWaiting()
    expect(
      within(dialog).getByText(/first run received from github.com\/acme\/api/i)
    ).toBeInTheDocument()
    expect(within(dialog).getByRole('link', { name: /open the run/i })).toHaveAttribute(
      'href',
      '/ci-cd?view=runs&run=run-9'
    )
  })

  it('shows a refused pipeline with the reason and the fix', async () => {
    refusals = [
      {
        at: new Date(Date.now() + 1000).toISOString(),
        repository: 'github.com/other/api',
        provider: 'github',
        reasons: ['owner_not_allowed'],
      },
    ]
    const dialog = await throughToWaiting()
    expect(within(dialog).getByText(/a pipeline was refused/i)).toBeInTheDocument()
    expect(
      within(dialog).getByText(/organization is not in the trust configuration/i)
    ).toBeInTheDocument()
    expect(within(dialog).getByText(/add the organization to owners/i)).toBeInTheDocument()
  })

  it.each([1280, 390])(
    'renders every step at %ipx with scrolling kept inside the snippet',
    async (w) => {
      Object.defineProperty(window, 'innerWidth', { value: w, configurable: true, writable: true })
      window.dispatchEvent(new Event('resize'))
      const dialog = await throughToWaiting()
      expect(dialog).toBeInTheDocument()
      // The steps wrap instead of widening the dialog.
      expect(within(dialog).getByRole('list', { name: /steps/i })).toHaveClass('flex-wrap')
    }
  )

  it('asks an administrator instead of offering the setup to readers', () => {
    render(<CISetupEntry canWrite={false} />)
    expect(screen.queryByRole('button', { name: /connect a pipeline/i })).not.toBeInTheDocument()
    expect(screen.getByText(/ask an administrator/i)).toBeInTheDocument()
  })

  it('needs the organization id for providers whose issuer names it', async () => {
    render(<CISetupEntry canWrite />)
    await userEvent.click(screen.getByRole('button', { name: /connect a pipeline/i }))
    const dialog = screen.getByRole('dialog')
    await userEvent.click(within(dialog).getByRole('radio', { name: 'CircleCI' }))
    await userEvent.click(within(dialog).getByRole('button', { name: /next/i }))
    await userEvent.type(within(dialog).getByLabelText(/organizations or owners/i), 'acme')
    expect(within(dialog).getByRole('button', { name: /create trust/i })).toBeDisabled()
    await userEvent.type(within(dialog).getByLabelText(/organization id/i), 'abc-123')
    expect(within(dialog).getByRole('button', { name: /create trust/i })).toBeEnabled()
  })
})

describe('Recent refused pipelines', () => {
  beforeEach(() => {
    refusals = []
  })

  it('lists refusals with translated reasons for CI writers', () => {
    refusals = [
      {
        at: '2026-10-14T00:00:00Z',
        repository: 'github.com/acme/api',
        provider: 'github',
        event: 'pull_request',
        ref: 'refs/pull/7/merge',
        reasons: ['fork_pull_request', 'some_new_code'],
      },
    ]
    render(<CITrustRefusals canWrite />)
    expect(screen.getByText('github.com/acme/api')).toBeInTheDocument()
    expect(screen.getByText(/pull request from a fork/i)).toBeInTheDocument()
    // An unknown code is shown as is.
    expect(screen.getByText('some_new_code')).toBeInTheDocument()
    expect(screen.getByText('pull_request, refs/pull/7/merge')).toBeInTheDocument()
  })

  it('says when nothing was refused', () => {
    render(<CITrustRefusals canWrite />)
    expect(screen.getByText(/no pipeline has been refused recently/i)).toBeInTheDocument()
  })

  it('renders nothing for readers', () => {
    refusals = [{ repository: 'x', reasons: ['replay'] }]
    const { container } = render(<CITrustRefusals canWrite={false} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('Connect a pipeline, organization already trusted', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    runs = []
    refusals = []
    apps = { data: [{ provider: 'github', account_login: 'acme' }] }
    trusts = [
      {
        id: 'trust-old',
        name: 'GitHub acme',
        provider: 'github',
        issuer: 'https://token.actions.githubusercontent.com',
        audience: 'openctem:tenant:t-123',
        default_branch: 'develop',
        enabled: true,
        rules: { owners: ['acme'] },
      },
    ]
  })

  it('reuses the trust that admits the organization instead of creating a duplicate', async () => {
    render(<CISetupEntry canWrite />)
    await userEvent.click(screen.getByRole('button', { name: /connect a pipeline/i }))
    const dialog = screen.getByRole('dialog')
    await userEvent.click(within(dialog).getByRole('button', { name: /next/i }))
    await userEvent.type(within(dialog).getByLabelText(/organizations or owners/i), 'ACME')
    await userEvent.click(within(dialog).getByRole('button', { name: /create trust/i }))
    expect(mockSave).not.toHaveBeenCalled()
    expect(await within(dialog).findByTestId('ci-setup-reused')).toHaveTextContent('GitHub acme')
    // The snippet follows the reused configuration's default branch.
    expect(within(dialog).getByTestId('ci-setup-snippet')).toHaveTextContent('branches: [develop]')
    // A run of the reused configuration from before does not count as the first run.
    runs = [{ id: 'old', trust_config_id: 'trust-old', created_at: '2020-01-01T00:00:00Z' }]
    await userEvent.click(within(dialog).getByRole('button', { name: /wait for the first run/i }))
    expect(within(dialog).getByText(/waiting for the first run/i)).toBeInTheDocument()
  })

  it('creates a trust with the default branch given', async () => {
    trusts = []
    mockSave.mockResolvedValue({
      id: 'trust-2',
      provider: 'github',
      audience: 'openctem:tenant:t-123',
      default_branch: 'trunk',
    })
    render(<CISetupEntry canWrite />)
    await userEvent.click(screen.getByRole('button', { name: /connect a pipeline/i }))
    const dialog = screen.getByRole('dialog')
    await userEvent.click(within(dialog).getByRole('button', { name: /next/i }))
    await userEvent.type(within(dialog).getByLabelText(/organizations or owners/i), 'acme')
    const branch = within(dialog).getByLabelText(/default branch/i)
    await userEvent.clear(branch)
    await userEvent.type(branch, 'trunk')
    await userEvent.click(within(dialog).getByRole('button', { name: /create trust/i }))
    await waitFor(() => expect(mockSave).toHaveBeenCalled())
    expect(mockSave.mock.calls[0][0].body.default_branch).toBe('trunk')
    expect(await within(dialog).findByTestId('ci-setup-snippet')).toHaveTextContent(
      'branches: [trunk]'
    )
  })
})
