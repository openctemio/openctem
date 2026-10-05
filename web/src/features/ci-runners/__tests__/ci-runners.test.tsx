import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CIRunsView } from '../components/ci-runs-view'
import { CITrustSettings } from '../components/ci-trust-settings'
import { ciRunsURL } from '../api/use-ci'
import { defaultAudience, githubSnippet, gitlabSnippet, parseList } from '../lib/ci'

// ── mocks ──────────────────────────────────────────────────

const mockSaveTrust = vi.fn()
let runs: unknown[] = []
let runDetail: unknown
let trust: unknown[] = []
let perms: string[] = []
let lastRunFilters: unknown

vi.mock('../api/use-ci', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../api/use-ci')>()),
  useCIRuns: (f: unknown) => {
    lastRunFilters = f
    return { data: { data: runs, total_pages: 1 }, isLoading: false, mutate: vi.fn() }
  },
  useCIRun: (id: string | null) => ({ data: id ? runDetail : undefined }),
  useTrustConfigs: () => ({ data: { data: trust }, isLoading: false, mutate: vi.fn() }),
  useSaveTrustConfig: () => ({ trigger: mockSaveTrust, isMutating: false }),
  useDeleteTrustConfig: () => ({ trigger: vi.fn(), isMutating: false }),
  useGatePolicies: () => ({
    data: {
      data: [],
      default: {
        scope_type: 'default',
        mode: 'enforce',
        fail_on_severity: 'high',
        new_findings_only: true,
        fail_on_kev: true,
      },
    },
    isLoading: false,
    mutate: vi.fn(),
  }),
  useSaveGatePolicy: () => ({ trigger: vi.fn(), isMutating: false }),
  useDeleteGatePolicy: () => ({ trigger: vi.fn(), isMutating: false }),
  useGateOverrides: () => ({ data: { data: [] }, isLoading: false, mutate: vi.fn() }),
  useCreateGateOverride: () => ({ trigger: vi.fn(), isMutating: false }),
  useRevokeGateOverride: () => ({ trigger: vi.fn(), isMutating: false }),
}))

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't-123', slug: 'acme', role: 'owner' } }),
}))

vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: (p: string) => perms.includes(p), isLoading: false }),
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/clipboard', () => ({ copyToClipboard: vi.fn(async () => true) }))
vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))

const failingRun = {
  id: 'r1',
  provider: 'github',
  repository: 'github.com/acme/api',
  branch: 'feature/login',
  pull_request: '17',
  commit_sha: 'abcdef1234567890',
  verdict: 'fail',
  findings_count: 3,
  actor: 'octocat',
  created_at: '2026-10-05T10:00:00Z',
}

describe('lib', () => {
  it('parses lists', () => {
    expect(parseList('acme, acme\nweb ,, ')).toEqual(['acme', 'web'])
  })

  it('pipeline snippets carry no secret and ask for an OIDC token', () => {
    const gh = githubSnippet({
      apiUrl: 'https://ctem.example',
      tenantId: 't1',
      audience: defaultAudience('t1'),
    })
    expect(gh).toContain('id-token: write')
    expect(gh).toContain('OPENCTEM_TENANT_ID: t1')
    expect(gh).not.toMatch(/API_KEY|secrets\./)
    // The default audience is implied; a custom one is passed.
    expect(gh).not.toContain('OPENCTEM_OIDC_AUDIENCE')
    expect(githubSnippet({ apiUrl: 'x', tenantId: 't1', audience: 'custom' })).toContain(
      'OPENCTEM_OIDC_AUDIENCE: custom'
    )
    const gl = gitlabSnippet({ apiUrl: 'https://ctem.example', tenantId: 't1', audience: 'aud-1' })
    expect(gl).toContain('id_tokens:')
    expect(gl).toContain('aud: aud-1')
    expect(gl).not.toMatch(/API_KEY/)
  })

  it('builds run list URLs', () => {
    expect(ciRunsURL({ verdict: 'fail', page: 2 })).toBe(
      '/api/v1/ci/runs?verdict=fail&page=2&per_page=25'
    )
  })
})

describe('CIRunsView', () => {
  beforeEach(() => {
    runs = []
    runDetail = undefined
  })

  it('explains how to start when there is no run', () => {
    render(<CIRunsView />)
    expect(screen.getByText('No CI runs yet')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /set up ci trust/i })).toHaveAttribute(
      'href',
      '/settings/scanning/ci'
    )
  })

  it('lists runs with their verdict and opens the reasons', async () => {
    runs = [failingRun]
    runDetail = {
      ...failingRun,
      pipeline_url: 'https://github.com/acme/api/actions/runs/1',
      verdict_detail: {
        verdict: 'fail',
        summary: { evaluated: 3, new: 1, pre_existing: 1, accepted: 1, blocking: 1 },
        baseline: { branch: 'main', known: true },
        policy: { source: 'default' },
        reasons: [
          {
            code: 'severity',
            title: 'SQL injection',
            message: 'severity high is at or above high',
            finding_id: 'f1',
            file: 'db.go',
            line: 42,
          },
        ],
      },
    }
    render(<CIRunsView />)
    const row = screen.getByTestId('ci-run-row')
    expect(within(row).getByText('github.com/acme/api')).toBeInTheDocument()
    expect(within(row).getByText('Fail')).toBeInTheDocument()
    expect(within(row).getByText('#17')).toBeInTheDocument()
    await userEvent.click(row)
    expect(await screen.findByText('SQL injection')).toBeInTheDocument()
    expect(screen.getByText('db.go:42')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /open finding/i })).toHaveAttribute(
      'href',
      '/findings/f1'
    )
    expect(screen.getByRole('link', { name: /pipeline/i })).toHaveAttribute(
      'rel',
      'noopener noreferrer nofollow'
    )
  })

  it('filters by verdict from page one', () => {
    render(<CIRunsView />)
    expect(lastRunFilters).toEqual({ verdict: '', page: 1 })
  })
})

describe('CITrustSettings', () => {
  beforeEach(() => {
    trust = []
    perms = []
    mockSaveTrust.mockReset()
  })

  it('a member cannot add trust or break-glass', async () => {
    perms = ['scans:ci:read']
    render(<CITrustSettings />)
    expect(screen.getByRole('button', { name: /add trust/i })).toBeDisabled()
    await userEvent.click(screen.getByRole('tab', { name: /break-glass/i }))
    expect(screen.getByRole('button', { name: /break-glass/i })).toBeDisabled()
  })

  it('refuses a configuration that names no owner or repository', async () => {
    perms = ['scans:ci:read', 'scans:ci:write']
    render(<CITrustSettings />)
    await userEvent.click(screen.getByRole('button', { name: /add trust/i }))
    await userEvent.type(screen.getByLabelText('Name'), 'GitHub org')
    const add = screen.getByRole('button', { name: /^add$/i })
    expect(add).toBeDisabled()
    await userEvent.type(screen.getByLabelText('Owners'), 'acme')
    expect(add).toBeEnabled()
    mockSaveTrust.mockResolvedValue({
      id: 'c1',
      name: 'GitHub org',
      provider: 'github',
      audience: 'openctem:tenant:t-123',
    })
    await userEvent.click(add)
    expect(mockSaveTrust).toHaveBeenCalledWith({
      id: undefined,
      body: expect.objectContaining({
        name: 'GitHub org',
        provider: 'github',
        rules: expect.objectContaining({ owners: ['acme'], allow_fork_pull_requests: false }),
      }),
    })
    // The snippet opens after a new configuration is added.
    expect(await screen.findByTestId('ci-snippet')).toHaveTextContent('OPENCTEM_TENANT_ID: t-123')
  })

  it('warns before admitting fork pull requests', async () => {
    perms = ['scans:ci:read', 'scans:ci:write']
    render(<CITrustSettings />)
    await userEvent.click(screen.getByRole('button', { name: /add trust/i }))
    await userEvent.click(screen.getByLabelText('Admit fork pull requests'))
    expect(screen.getByText(/fork code would act/i)).toBeInTheDocument()
  })
})
