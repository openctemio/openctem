import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CIRunsView } from '../components/ci-runs-view'
import { CITrustSettings } from '../components/ci-trust-settings'
import { ciRunsURL } from '../api/use-ci'
import {
  PROVIDER_TRAITS,
  defaultAudience,
  githubSnippet,
  gitlabSnippet,
  issuerFor,
  organizationFromIssuer,
  parseList,
  snippetFor,
} from '../lib/ci'

// Radix Select uses pointer capture and scrollIntoView, which jsdom lacks.
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}
Element.prototype.scrollIntoView ??= () => {}

// ── mocks ──────────────────────────────────────────────────

const mockSaveTrust = vi.fn()
const mockPreview = vi.fn()
const mockSaveSettings = vi.fn()
let ciSettings: { require_oidc: boolean } | undefined = { require_oidc: true }
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
  useCISettings: () => ({ data: ciSettings, mutate: vi.fn() }),
  useSaveCISettings: () => ({ trigger: mockSaveSettings, isMutating: false }),
  useSaveTrustConfig: () => ({ trigger: mockSaveTrust, isMutating: false }),
  useDeleteTrustConfig: () => ({ trigger: vi.fn(), isMutating: false }),
  usePreviewTrustConfig: () => ({ trigger: mockPreview, isMutating: false }),
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

  it('builds each provider issuer from what names the organization', () => {
    const org = '00000000-1111-4222-8333-444455556666'
    expect(issuerFor('azure_devops', org.toUpperCase())).toBe(
      `https://vstoken.dev.azure.com/${org}`
    )
    expect(issuerFor('circleci', org)).toBe(`https://oidc.circleci.com/org/${org}`)
    const bb = issuerFor('bitbucket', 'Acme')
    expect(bb).toBe('https://api.bitbucket.org/2.0/workspaces/acme/pipelines-config/identity/oidc')
    expect(organizationFromIssuer('bitbucket', bb)).toBe('acme')
    expect(organizationFromIssuer('circleci', `https://oidc.circleci.com/org/${org}`)).toBe(org)
    expect(issuerFor('jenkins', ' https://ci.example/oidc ')).toBe('https://ci.example/oidc')
    expect(issuerFor('circleci', '  ')).toBeUndefined()
  })

  it('new provider snippets use the job identity, never a stored secret', () => {
    const input = {
      apiUrl: 'https://ctem.example',
      tenantId: 't1',
      audience: defaultAudience('t1'),
    }
    for (const p of ['azure_devops', 'bitbucket', 'circleci', 'jenkins'] as const) {
      const s = snippetFor(p, input)
      expect(s).toContain('t1')
      expect(s).not.toMatch(/API_KEY|secrets\./)
    }
    expect(snippetFor('bitbucket', input)).toContain('- openctem:tenant:t1')
    expect(snippetFor('circleci', input)).toContain('circleci run oidc get')
    expect(snippetFor('azure_devops', input)).toContain('SYSTEM_ACCESSTOKEN: $(System.AccessToken)')
    expect(snippetFor('jenkins', input)).toContain('withCredentials')
  })

  it('offers only the rules a provider token can back', () => {
    expect(PROVIDER_TRAITS.azure_devops).toMatchObject({
      events: false,
      environments: false,
      protectedRef: 'none',
    })
    expect(PROVIDER_TRAITS.bitbucket.repositoriesById).toBe(true)
    expect(PROVIDER_TRAITS.circleci.tenantAudience).toBe(true)
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
      '/ci-cd?tab=setup'
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

  it('warns while CI sensor keys are accepted and lets an administrator require OIDC', async () => {
    perms = ['scans:ci:read', 'scans:ci:write']
    ciSettings = { require_oidc: false }
    mockSaveSettings.mockResolvedValue({ require_oidc: true })
    render(<CITrustSettings />)
    expect(screen.getByTestId('ci-require-oidc-banner')).toHaveTextContent(/still accepted/i)
    await userEvent.click(screen.getByLabelText('Require OIDC for CI'))
    expect(mockSaveSettings).toHaveBeenCalledWith({ require_oidc: true })
    ciSettings = { require_oidc: true }
  })

  it('shows no banner when OIDC is required, and a member cannot change it', () => {
    perms = ['scans:ci:read']
    ciSettings = { require_oidc: true }
    render(<CITrustSettings />)
    expect(screen.queryByTestId('ci-require-oidc-banner')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Require OIDC for CI')).toBeDisabled()
  })

  it('warns before admitting fork pull requests', async () => {
    perms = ['scans:ci:read', 'scans:ci:write']
    render(<CITrustSettings />)
    await userEvent.click(screen.getByRole('button', { name: /add trust/i }))
    await userEvent.click(screen.getByLabelText('Admit fork pull requests'))
    expect(screen.getByText(/fork code would act/i)).toBeInTheDocument()
  })

  it('guides a Bitbucket trust: workspace, its UUID, repositories by UUID', async () => {
    perms = ['scans:ci:read', 'scans:ci:write']
    render(<CITrustSettings />)
    await userEvent.click(screen.getByRole('button', { name: /add trust/i }))
    await userEvent.click(screen.getByRole('combobox', { name: /provider/i }))
    await userEvent.click(await screen.findByRole('option', { name: 'Bitbucket Pipelines' }))
    expect(screen.queryByLabelText('Events')).not.toBeInTheDocument()
    expect(screen.getByText(/the token signs the id, never the name/i)).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('Name'), 'BB')
    await userEvent.type(screen.getByLabelText('Workspace'), 'acme')
    await userEvent.type(screen.getByLabelText('Workspace UUID'), 'ws-uuid')
    await userEvent.type(screen.getByLabelText('Owners'), 'acme')
    mockSaveTrust.mockResolvedValue({
      id: 'c2',
      name: 'BB',
      provider: 'bitbucket',
      audience: 'openctem:tenant:t-123',
    })
    await userEvent.click(screen.getByRole('button', { name: /^add$/i }))
    expect(mockSaveTrust).toHaveBeenCalledWith({
      id: undefined,
      body: expect.objectContaining({
        provider: 'bitbucket',
        issuer: 'https://api.bitbucket.org/2.0/workspaces/acme/pipelines-config/identity/oidc',
        rules: expect.objectContaining({ owners: ['acme'], workspace_uuid: 'ws-uuid', events: [] }),
      }),
    })
  })

  it('shows the fixed Azure audience and refuses pull request builds by default', async () => {
    perms = ['scans:ci:read', 'scans:ci:write']
    render(<CITrustSettings />)
    await userEvent.click(screen.getByRole('button', { name: /add trust/i }))
    await userEvent.click(screen.getByRole('combobox', { name: /provider/i }))
    await userEvent.click(await screen.findByRole('option', { name: 'Azure Pipelines' }))
    expect(screen.getByTestId('ci-fixed-audience')).toHaveTextContent('api://AzureADTokenExchange')
    expect(screen.queryByLabelText('Audience')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Protected branches and tags only')).not.toBeInTheDocument()
    expect(screen.getByText(/cannot tell a fork/i)).toBeInTheDocument()
    // No organization id yet: nothing to check a sample against, nothing to save.
    expect(screen.queryByTestId('ci-trust-preview')).not.toBeInTheDocument()
  })

  it('checks a sample token against the draft and shows the outcome', async () => {
    perms = ['scans:ci:read', 'scans:ci:write']
    mockPreview.mockResolvedValue({
      verified: true,
      expired: true,
      admitted: false,
      refusal: { code: 'repository_not_allowed', detail: 'repository "acme/web" is not listed' },
      normalized: { repository: 'acme/web', ref: 'refs/heads/main', commit_verified: true },
      claims: { iss: 'https://token.actions.githubusercontent.com' },
    })
    render(<CITrustSettings />)
    await userEvent.click(screen.getByRole('button', { name: /add trust/i }))
    await userEvent.type(screen.getByLabelText('Owners'), 'acme')
    await userEvent.type(screen.getByLabelText('Check a sample token'), 'a.b.c')
    await userEvent.click(screen.getByRole('button', { name: /check token/i }))
    expect(mockPreview).toHaveBeenCalledWith(
      expect.objectContaining({
        id_token: 'a.b.c',
        config: expect.objectContaining({
          provider: 'github',
          rules: expect.objectContaining({ owners: ['acme'] }),
        }),
      })
    )
    const result = await screen.findByTestId('ci-trust-preview-result')
    expect(within(result).getByText('Signature verified')).toBeInTheDocument()
    expect(within(result).getByText('Expired')).toBeInTheDocument()
    expect(within(result).getByText(/repository_not_allowed/)).toBeInTheDocument()
    expect(mockSaveTrust).not.toHaveBeenCalled()
  })

  it('explains that GitHub proves protected refs with deployment environments', async () => {
    perms = ['scans:ci:read', 'scans:ci:write']
    render(<CITrustSettings />)
    await userEvent.click(screen.getByRole('button', { name: /add trust/i }))
    expect(screen.queryByText(/deployment branch rules/i)).not.toBeInTheDocument()
    await userEvent.click(screen.getByLabelText('Protected branches and tags only'))
    expect(screen.getByText(/deployment branch rules/i)).toBeInTheDocument()
  })
})
