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
type PollCall = [{ provider?: string }, { enabled?: boolean; refreshInterval?: number }]
const runsCalls: PollCall[] = []
const trustCalls: PollCall[1][] = []

vi.mock('../api/use-ci', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../api/use-ci')>()),
  useSaveTrustConfig: () => ({ trigger: mockSave, isMutating: false }),
  useCIRunnerRelease: () => 'v0.9.2',
  useSCMApps: () => ({ data: apps }),
  useTrustConfigs: (o: PollCall[1]) => {
    trustCalls.push(o)
    return { data: { data: trusts } }
  },
  useCIRuns: (f: PollCall[0], o: PollCall[1]) => {
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

async function open() {
  render(<CISetupEntry canWrite />)
  await userEvent.click(screen.getByRole('button', { name: /connect a ci provider/i }))
  return screen.getByRole('dialog')
}

/** GitHub: the app installation is offered as the owner. */
async function githubToWaiting() {
  const dialog = await open()
  await userEvent.click(within(dialog).getByRole('radio', { name: 'GitHub Actions' }))
  await userEvent.click(within(dialog).getByRole('button', { name: /next/i }))
  const connect = within(dialog).getByRole('button', { name: /^connect$/i })
  expect(connect).toBeDisabled()
  await userEvent.click(within(dialog).getByRole('button', { name: 'acme' }))
  await userEvent.click(connect)
  await waitFor(() => expect(mockSave).toHaveBeenCalled())
  const body = mockSave.mock.calls[0][0].body
  expect(body.provider).toBe('github')
  expect(body.rules.owners).toEqual(['acme'])
  expect(body.rules.allow_fork_pull_requests).toBe(false)
  // Snippet: the organization's tenant, the CI runner release the API names.
  expect(await within(dialog).findByTestId('ci-setup-snippet')).toHaveTextContent('t-123')
  expect(within(dialog).getByTestId('ci-setup-snippet')).toHaveTextContent('@v0.9.2')
  await userEvent.click(within(dialog).getByRole('button', { name: /i added it/i }))
  return dialog
}

describe('Connect a CI provider', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    runs = []
    refusals = []
    runsCalls.length = 0
    trustCalls.length = 0
    apps = { data: [{ provider: 'github', account_login: 'acme' }] }
    trusts = []
    mockSave.mockResolvedValue({
      id: 'trust-1',
      provider: 'github',
      audience: 'openctem:tenant:t-123',
    })
  })

  it('starts on GitLab and shows the address exactly as tokens carry it', async () => {
    const dialog = await open()
    expect(within(dialog).getByRole('radio', { name: 'GitLab CI' })).toHaveAttribute(
      'aria-checked',
      'true'
    )
    expect(
      within(dialog).getByText(/tokens must name exactly: https:\/\/gitlab.com/i)
    ).toBeVisible()
    await userEvent.type(
      within(dialog).getByLabelText(/your gitlab address/i),
      'GitLab.Example.com/'
    )
    expect(
      within(dialog).getByText(/tokens must name exactly: https:\/\/gitlab.example.com$/i)
    ).toBeVisible()
    expect(within(dialog).queryByTestId('ci-connect-private')).not.toBeInTheDocument()
  })

  it('warns before a private GitLab address that the platform must reach it', async () => {
    const dialog = await open()
    await userEvent.type(within(dialog).getByLabelText(/your gitlab address/i), '192.168.1.10')
    expect(within(dialog).getByTestId('ci-connect-private')).toHaveTextContent(
      /a platform administrator can allow it/i
    )
  })

  it('admits several GitLab groups with one configuration, protected branches by default', async () => {
    mockSave.mockResolvedValue({
      id: 'trust-g',
      provider: 'gitlab',
      audience: 'openctem:tenant:t-123',
    })
    const dialog = await open()
    await userEvent.type(
      within(dialog).getByLabelText(/your gitlab address/i),
      'gitlab.example.com/'
    )
    await userEvent.click(within(dialog).getByRole('button', { name: /next/i }))
    expect(
      within(dialog).getByRole('radio', { name: /every project in these groups/i })
    ).toBeChecked()
    expect(within(dialog).getByRole('radio', { name: /only protected branches/i })).toBeChecked()
    expect(within(dialog).getByText(/one configuration covers many groups/i)).toBeVisible()
    const groups = within(dialog).getByLabelText(/^group$/i)
    await userEvent.type(groups, 'acme{enter}beta/team{enter}')
    await userEvent.click(within(dialog).getByRole('button', { name: /^connect$/i }))
    await waitFor(() => expect(mockSave).toHaveBeenCalled())
    const body = mockSave.mock.calls[0][0].body
    expect(body.issuer).toBe('https://gitlab.example.com')
    expect(body.rules.owners).toEqual(['acme'])
    expect(body.rules.repositories).toEqual(['beta/team/**'])
    expect(body.rules.require_protected_ref).toBe(true)
    expect(body.rules.refs).toEqual([])
    expect(await within(dialog).findByTestId('ci-setup-snippet')).toHaveTextContent('t-123')
  })

  it('warns when a whole group is opened to every branch', async () => {
    const dialog = await open()
    await userEvent.click(within(dialog).getByRole('button', { name: /next/i }))
    expect(within(dialog).queryByTestId('ci-connect-all-branches')).not.toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('radio', { name: /every branch/i }))
    expect(within(dialog).getByTestId('ci-connect-all-branches')).toBeVisible()
    await userEvent.click(within(dialog).getByRole('radio', { name: /only these projects/i }))
    expect(within(dialog).queryByTestId('ci-connect-all-branches')).not.toBeInTheDocument()
  })

  it('waits for the first job and polls runs and refusals only (two reviewed polls)', async () => {
    const dialog = await githubToWaiting()
    expect(within(dialog).getByText(/waiting for the first job/i)).toBeInTheDocument()
    expect(
      runsCalls.some(
        ([f, o]) => f.provider === 'github' && o.enabled && (o.refreshInterval ?? 0) > 0
      )
    ).toBe(true)
    expect(trustCalls.some((o) => (o?.refreshInterval ?? 0) > 0)).toBe(false)
  })

  it('turns green when the configuration accepted a job', async () => {
    trusts = [
      {
        id: 'trust-1',
        provider: 'github',
        last_used_at: new Date(Date.now() + 1000).toISOString(),
      },
    ]
    const dialog = await githubToWaiting()
    expect(within(dialog).getByTestId('ci-connect-done')).toHaveTextContent(/a job was accepted/i)
  })

  it('says when the first run arrived and links to it', async () => {
    runs = [{ id: 'run-9', trust_config_id: 'trust-1', repository: 'github.com/acme/api' }]
    const dialog = await githubToWaiting()
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
    const dialog = await githubToWaiting()
    expect(within(dialog).getByText(/a pipeline was refused/i)).toBeInTheDocument()
    expect(
      within(dialog).getByText(/group or organization is not in the configuration/i)
    ).toBeInTheDocument()
    expect(
      within(dialog).getByText(/add the group or organization to the configuration/i)
    ).toBeInTheDocument()
  })

  it.each([1280, 390])('renders every step at %ipx with the steps wrapping', async (w) => {
    Object.defineProperty(window, 'innerWidth', { value: w, configurable: true, writable: true })
    window.dispatchEvent(new Event('resize'))
    const dialog = await githubToWaiting()
    expect(within(dialog).getByRole('list', { name: /steps/i })).toHaveClass('flex-wrap')
  })

  it('asks an administrator instead of offering the setup to readers', () => {
    render(<CISetupEntry canWrite={false} />)
    expect(screen.queryByRole('button', { name: /connect a ci provider/i })).not.toBeInTheDocument()
    expect(screen.getByText(/ask an administrator/i)).toBeInTheDocument()
  })

  it('needs the organization id for providers whose issuer names it', async () => {
    const dialog = await open()
    await userEvent.click(within(dialog).getByRole('radio', { name: 'CircleCI' }))
    expect(within(dialog).getByRole('button', { name: /next/i })).toBeDisabled()
    await userEvent.type(within(dialog).getByLabelText(/organization id/i), 'abc-123')
    await userEvent.click(within(dialog).getByRole('button', { name: /next/i }))
    expect(within(dialog).getByRole('button', { name: /^connect$/i })).toBeDisabled()
    await userEvent.type(within(dialog).getByLabelText(/organizations or owners/i), 'acme{enter}')
    expect(within(dialog).getByRole('button', { name: /^connect$/i })).toBeEnabled()
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

  it('offers the exact pipeline file and the branch as one-click fixes', async () => {
    const message =
      'CI token from g/p refused: pipeline definition "gitlab.example.com/g/p//.gitlab-ci.yml@refs/heads/main" is not listed'
    refusals = [
      {
        at: '2026-10-14T00:00:00Z',
        repository: 'g/p',
        provider: 'gitlab',
        ref: 'refs/heads/feature/x',
        reasons: ['workflow_not_allowed', 'ref_not_allowed'],
        message,
      },
    ]
    const onFix = vi.fn()
    render(<CITrustRefusals canWrite onFix={onFix} canFix={() => true} />)
    expect(screen.getByTestId('ci-refusal-definition')).toHaveTextContent(
      'gitlab.example.com/g/p//.gitlab-ci.yml@refs/heads/main'
    )
    await userEvent.click(screen.getByRole('button', { name: /add this pipeline file/i }))
    expect(onFix.mock.calls[0][1]).toEqual({
      kind: 'addDefinition',
      value: 'gitlab.example.com/g/p//.gitlab-ci.yml@refs/heads/main',
    })
    await userEvent.click(screen.getByRole('button', { name: /allow branch feature\/x/i }))
    expect(onFix.mock.calls[1][1]).toEqual({ kind: 'allowBranch', value: 'feature/x' })
  })

  it('offers no fix when no configuration can take it', () => {
    refusals = [
      {
        at: '2026-10-14T00:00:00Z',
        repository: 'g/p',
        ref: 'refs/heads/x',
        reasons: ['ref_not_allowed'],
      },
    ]
    render(<CITrustRefusals canWrite onFix={vi.fn()} canFix={() => false} />)
    expect(screen.queryByRole('button', { name: /allow branch/i })).not.toBeInTheDocument()
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

describe('Connect a CI provider, organization already trusted', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    runs = []
    refusals = []
    apps = { data: [] }
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

  async function githubOwner(owner: string) {
    const dialog = await open()
    await userEvent.click(within(dialog).getByRole('radio', { name: 'GitHub Actions' }))
    await userEvent.click(within(dialog).getByRole('button', { name: /next/i }))
    await userEvent.type(
      within(dialog).getByLabelText(/organizations or owners/i),
      `${owner}{enter}`
    )
    return dialog
  }

  it('reuses the trust that admits the organization instead of creating a duplicate', async () => {
    const dialog = await githubOwner('ACME')
    await userEvent.click(within(dialog).getByRole('button', { name: /^connect$/i }))
    expect(mockSave).not.toHaveBeenCalled()
    expect(await within(dialog).findByTestId('ci-setup-reused')).toHaveTextContent('GitHub acme')
    // The snippet follows the reused configuration's default branch.
    expect(within(dialog).getByTestId('ci-setup-snippet')).toHaveTextContent('branches: [develop]')
    // A run of the reused configuration from before does not count as the first run.
    runs = [{ id: 'old', trust_config_id: 'trust-old', created_at: '2020-01-01T00:00:00Z' }]
    await userEvent.click(within(dialog).getByRole('button', { name: /i added it/i }))
    expect(within(dialog).getByText(/waiting for the first job/i)).toBeInTheDocument()
  })

  it('creates a trust with the default branch given', async () => {
    trusts = []
    mockSave.mockResolvedValue({
      id: 'trust-2',
      provider: 'github',
      audience: 'openctem:tenant:t-123',
      default_branch: 'trunk',
    })
    const dialog = await githubOwner('acme')
    const branch = within(dialog).getByLabelText(/^default branch$/i)
    await userEvent.clear(branch)
    await userEvent.type(branch, 'trunk')
    await userEvent.click(within(dialog).getByRole('button', { name: /^connect$/i }))
    await waitFor(() => expect(mockSave).toHaveBeenCalled())
    expect(mockSave.mock.calls[0][0].body.default_branch).toBe('trunk')
    expect(await within(dialog).findByTestId('ci-setup-snippet')).toHaveTextContent(
      'branches: [trunk]'
    )
  })
})
