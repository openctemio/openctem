import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CIRunsView } from '../components/ci-runs-view'
import { ApiClientError } from '@/lib/api/error-handler'
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
  findCoveringTrust,
  releaseBefore,
  CI_PROVIDERS,
  CI_RELEASE,
} from '../lib/ci'
import type { CITrustConfig } from '../types'

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
let runError: unknown
let trust: unknown[] = []
let perms: string[] = []
let lastRunFilters: unknown
let gatePolicies: unknown[] = []
let overrides: unknown[] = []
const mockDeletePolicy = vi.fn()
const mockSavePolicy = vi.fn()
const mockRevokeOverride = vi.fn()

vi.mock('../api/use-ci', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../api/use-ci')>()),
  useCIRuns: (f: unknown) => {
    lastRunFilters = f
    return { data: { data: runs, total_pages: 1 }, isLoading: false, mutate: vi.fn() }
  },
  useCIRun: (id: string | null) => ({
    data: id ? runDetail : undefined,
    error: id ? runError : undefined,
  }),
  useTrustConfigs: () => ({ data: { data: trust }, isLoading: false, mutate: vi.fn() }),
  useCISettings: () => ({ data: ciSettings, mutate: vi.fn() }),
  useSaveCISettings: () => ({ trigger: mockSaveSettings, isMutating: false }),
  useSaveTrustConfig: () => ({ trigger: mockSaveTrust, isMutating: false }),
  useDeleteTrustConfig: () => ({ trigger: vi.fn(), isMutating: false }),
  usePreviewTrustConfig: () => ({ trigger: mockPreview, isMutating: false }),
  useGatePolicies: () => ({
    data: {
      data: gatePolicies,
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
  useSaveGatePolicy: () => ({ trigger: mockSavePolicy, isMutating: false }),
  useDeleteGatePolicy: () => ({ trigger: mockDeletePolicy, isMutating: false }),
  useGateOverrides: () => ({ data: { data: overrides }, isLoading: false, mutate: vi.fn() }),
  useCreateGateOverride: () => ({ trigger: vi.fn(), isMutating: false }),
  useRevokeGateOverride: () => ({ trigger: mockRevokeOverride, isMutating: false }),
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
    expect(gh).toContain('tenant-id: t1')
    expect(gh).toContain(`uses: openctemio/ci/.github/workflows/scan.yml@${CI_RELEASE}`)
    expect(gh).not.toMatch(/API_KEY|secrets\./)
    // The default audience is implied; a custom one is passed.
    expect(gh).not.toContain('oidc-audience')
    expect(githubSnippet({ apiUrl: 'x', tenantId: 't1', audience: 'custom' })).toContain(
      'oidc-audience: custom'
    )
    const gl = gitlabSnippet({
      apiUrl: 'https://ctem.example',
      tenantId: 't1',
      audience: defaultAudience('t1'),
    })
    expect(gl).toContain(`openctemio/ci/${CI_RELEASE}/gitlab/templates/all.yml`)
    expect(gl).toContain('OPENCTEM_TENANT_ID: t1')
    expect(gl).not.toContain('id_tokens')
    expect(gl).not.toMatch(/API_KEY/)
    // A custom audience overrides every job's ID token request.
    const custom = gitlabSnippet({
      apiUrl: 'https://ctem.example',
      tenantId: 't1',
      audience: 'aud-1',
    })
    expect(custom).toContain('aud: aud-1')
    for (const job of [
      'openctem-sast',
      'openctem-sca',
      'openctem-secrets',
      'openctem-iac',
      'openctem-gate',
    ]) {
      expect(custom).toContain(`${job}: *openctem-audience`)
    }
  })

  it('the GitHub snippet scans the default branch and grants what the pinned release needs', () => {
    const input = {
      apiUrl: 'https://ctem.example',
      tenantId: 't1',
      audience: defaultAudience('t1'),
    }
    expect(githubSnippet(input)).toContain('branches: [main]')
    expect(githubSnippet({ ...input, defaultBranch: 'develop' })).toContain('branches: [develop]')
    // A branch name YAML would misread is quoted.
    expect(githubSnippet({ ...input, defaultBranch: 'x: y' })).toContain('branches: ["x: y"]')
    // The reusable workflow's scan job asks for security-events: write, and
    // GitHub refuses to start a called job that asks for more than its caller
    // grants: the snippet always grants it.
    expect(githubSnippet(input)).toContain('security-events: write')
    expect(releaseBefore('v0.2.0', 'v0.3.0')).toBe(true)
    expect(releaseBefore('v0.3.0', 'v0.3.0')).toBe(false)
    expect(releaseBefore('v0.10.0', 'v0.3.0')).toBe(false)
  })

  it('other CI systems run the pinned release image, never the moving edge build', () => {
    const input = {
      apiUrl: 'https://ctem.example',
      tenantId: 't1',
      audience: defaultAudience('t1'),
    }
    // Jenkins runs openctem-ci installed on its build node, not an image.
    for (const p of ['azure_devops', 'bitbucket', 'circleci'] as const) {
      const s = snippetFor(p, input)
      expect(s).toContain(`ghcr.io/openctemio/ci:${CI_RELEASE}`)
    }
    for (const p of CI_PROVIDERS) expect(snippetFor(p, input)).not.toContain('ci:edge')
  })

  it('reads a GitHub issuer back only when it is not github.com', () => {
    expect(organizationFromIssuer('github', 'https://token.actions.githubusercontent.com')).toBe('')
    expect(organizationFromIssuer('github', 'https://github.example.com/_services/token')).toBe(
      'https://github.example.com/_services/token'
    )
  })

  it('the wizard never reuses a GitHub Enterprise trust for github.com', () => {
    const ghes = {
      id: 'e',
      provider: 'github',
      issuer: 'https://github.example.com/_services/token',
      enabled: true,
      rules: { owners: ['acme'] },
    } as CITrustConfig
    expect(findCoveringTrust([ghes], 'github', '', ['acme'])).toBeUndefined()
  })

  it('finds a trust configuration that already admits the owners', () => {
    const gh = {
      id: 'a',
      name: 'GitHub acme',
      provider: 'github',
      issuer: 'https://token.actions.githubusercontent.com',
      enabled: true,
      rules: { owners: ['Acme', 'web'] },
    } as CITrustConfig
    const gl = {
      id: 'b',
      provider: 'gitlab',
      issuer: 'https://gitlab.com',
      enabled: true,
      rules: { owners: ['platform'] },
    } as CITrustConfig
    const off = { ...gh, id: 'c', enabled: false } as CITrustConfig
    expect(findCoveringTrust([off, gh], 'github', '', ['acme'])?.id).toBe('a')
    expect(findCoveringTrust([gh], 'github', '', ['acme', 'other'])).toBeUndefined()
    expect(findCoveringTrust([off], 'github', '', ['acme'])).toBeUndefined()
    expect(findCoveringTrust([gh], 'gitlab', '', ['acme'])).toBeUndefined()
    // An empty GitLab URL is gitlab.com; another host is another issuer.
    expect(findCoveringTrust([gl], 'gitlab', '', ['platform'])?.id).toBe('b')
    expect(findCoveringTrust([gl], 'gitlab', 'https://git.example', ['platform'])).toBeUndefined()
    expect(findCoveringTrust([gh], 'github', '', [])).toBeUndefined()
  })

  it('no snippet runs the sensor image or its removed CI flags', () => {
    const input = {
      apiUrl: 'https://ctem.example',
      tenantId: 't1',
      audience: defaultAudience('t1'),
    }
    for (const p of CI_PROVIDERS) {
      const s = snippetFor(p, input)
      expect(s).not.toMatch(/openctemio\/sensor|-auto-ci|-push\b/)
    }
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
    expect(PROVIDER_TRAITS.github.workflowRefs).toBe(true)
    expect(PROVIDER_TRAITS.gitlab.workflowRefs).toBe(true)
    expect(PROVIDER_TRAITS.jenkins.workflowRefs).toBe(false)
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
    runError = undefined
    window.history.replaceState({}, '', '/')
  })

  it("a run out of the caller's access says so instead of a bare load error", () => {
    runError = new ApiClientError('CI run not found', 'NOT_FOUND', 404)
    window.history.replaceState({}, '', '/?run=r9')
    render(<CIRunsView />)
    expect(screen.getByText('This run is not available to you')).toBeInTheDocument()
    expect(screen.queryByText(/failed to load/i)).not.toBeInTheDocument()
  })

  it('explains how to start when there is no run', () => {
    perms = ['scans:ci:write']
    render(<CIRunsView />)
    expect(screen.getByText('No CI runs yet')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /connect a pipeline/i })).toBeInTheDocument()
    perms = []
  })

  it('tells a reader the runs they see follow their access, not that none exist', () => {
    perms = []
    render(<CIRunsView />)
    expect(screen.getByText('No CI runs you can see')).toBeInTheDocument()
    expect(screen.queryByText('No CI runs yet')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /connect a pipeline/i })).not.toBeInTheDocument()
  })

  it('says no run matches when a verdict filter hides them', () => {
    window.history.replaceState({}, '', '/?verdict=fail')
    render(<CIRunsView />)
    expect(screen.getByText('No runs with this verdict')).toBeInTheDocument()
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

  const judgedRun = {
    ...failingRun,
    id: 'r2',
    repository_asset_id: 'asset-1',
    commit_sha: 'abcdef1234567890abcdef1234567890abcdef12',
    commit_verified: true,
    status: 'evaluated',
    scan_failures: 0,
    tools: [{ name: 'semgrep', version: '1.179.0' }],
    decoration_state: 'failed',
    decoration_detail: 'could not post the check: GitHub answered 403',
    verdict_detail: {
      verdict: 'fail',
      repo_file: 'applied',
      links: { findings: '/findings?asset_id=asset-1' },
      summary: { evaluated: 2, new: 2, pre_existing: 0, accepted: 0, blocking: 1, monitored: 3 },
      reasons: [
        { code: 'severity', title: 'SQL injection', message: 'high', mode: 'block' },
        { code: 'severity', title: 'Weak hash', message: 'medium', mode: 'comment' },
      ],
    },
  }

  it('separates blocking from comment-only reasons and shows how the check was posted', async () => {
    runDetail = judgedRun
    window.history.replaceState({}, '', '/ci-cd?view=runs&run=r2')
    render(<CIRunsView />)
    const blocking = await screen.findByRole('list', { name: 'Blocking' })
    expect(within(blocking).getByText('SQL injection')).toBeInTheDocument()
    expect(within(blocking).queryByText('Weak hash')).not.toBeInTheDocument()
    const comment = screen.getByRole('list', { name: /comment only/i })
    expect(within(comment).getByText('Weak hash')).toBeInTheDocument()
    expect(screen.getByText(/3 more in monitor mode/)).toBeInTheDocument()
    const deco = screen.getByTestId('ci-run-decoration')
    expect(within(deco).getByText('Failed')).toBeInTheDocument()
    expect(within(deco).getByText(/GitHub answered 403/)).toBeInTheDocument()
    expect(screen.getByText('semgrep 1.179.0')).toBeInTheDocument()
    expect(screen.getByText('Applied (tightened the policy)')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /view the run's findings/i })).toHaveAttribute(
      'href',
      '/findings?asset_id=asset-1'
    )
  })

  it('offers break-glass on a failed run to administrators only', async () => {
    runDetail = judgedRun
    window.history.replaceState({}, '', '/ci-cd?view=runs&run=r2')
    perms = []
    const { unmount } = render(<CIRunsView />)
    await screen.findByRole('list', { name: 'Blocking' })
    expect(screen.queryByTestId('ci-run-break-glass')).not.toBeInTheDocument()
    unmount()
    perms = ['scans:ci:override']
    render(<CIRunsView />)
    await userEvent.click(await screen.findByTestId('ci-run-break-glass'))
    expect(await screen.findByLabelText('Commit')).toHaveValue(judgedRun.commit_sha)
    expect(screen.getByLabelText('Repository asset ID')).toHaveValue('asset-1')
    perms = []
  })

  it('says when a pass came through a break-glass override', async () => {
    runDetail = {
      ...judgedRun,
      verdict: 'pass',
      would_fail: true,
      override: {
        id: 'o1',
        reason: 'release hotfix',
        created_by: 'admin@acme.test',
        expires_at: '2099-01-01T00:00:00Z',
      },
      verdict_detail: {
        ...judgedRun.verdict_detail,
        verdict: 'pass',
        would_fail: true,
        reasons: [],
      },
    }
    window.history.replaceState({}, '', '/ci-cd?view=runs&run=r2')
    render(<CIRunsView />)
    const callout = await screen.findByTestId('ci-run-override')
    expect(within(callout).getByText(/admin@acme.test: release hotfix/)).toBeInTheDocument()
    expect(screen.getByText('Pass (override or warn)')).toBeInTheDocument()
    expect(screen.queryByTestId('ci-run-break-glass')).not.toBeInTheDocument()
  })

  it('marks a running run and a pass that would have failed in the list', () => {
    runs = [
      { ...failingRun, id: 'a', verdict: undefined, status: 'running' },
      { ...failingRun, id: 'b', verdict: 'pass', would_fail: true, status: 'evaluated' },
    ]
    render(<CIRunsView />)
    const rows = screen.getAllByTestId('ci-run-row')
    expect(within(rows[0]).getByText('Running')).toBeInTheDocument()
    expect(within(rows[1]).getByText('Pass (override or warn)')).toBeInTheDocument()
  })

  it.each([390, 1280])('renders the run detail at %ipx without fixed-width rows', async (width) => {
    window.innerWidth = width
    window.dispatchEvent(new Event('resize'))
    runDetail = {
      ...judgedRun,
      repository: 'github.com/acme/' + 'a-very-long-repository-name'.repeat(4),
    }
    window.history.replaceState({}, '', '/ci-cd?view=runs&run=r2')
    render(<CIRunsView />)
    const blocking = await screen.findByRole('list', { name: 'Blocking' })
    // Labels shrink on a phone (minmax), long values wrap instead of
    // widening the sheet.
    const grid = document.querySelector('dl')
    expect(grid?.className).toContain('minmax(6rem,8rem)')
    expect(within(blocking).getByText('SQL injection').className).toContain('break-words')
    expect(
      screen.getByRole('heading', { name: /a-very-long-repository-name/ }).className
    ).toContain('break-words')
  })

  it('keeps the open run in the URL', async () => {
    runs = [failingRun]
    runDetail = { ...failingRun }
    render(<CIRunsView />)
    await userEvent.click(screen.getByTestId('ci-run-row'))
    expect(window.location.search).toContain('run=r1')
  })
})

describe('CITrustSettings sections', () => {
  it('opens the section the URL names and keeps the chosen one in the URL', async () => {
    window.history.replaceState({}, '', '/?section=gate')
    render(<CITrustSettings />)
    expect(screen.getByRole('tab', { name: 'Gate policy' })).toHaveAttribute(
      'aria-selected',
      'true'
    )
    await userEvent.click(screen.getByRole('tab', { name: 'Pull request feedback' }))
    expect(window.location.search).toContain('section=feedback')
    window.history.replaceState({}, '', '/?section=bogus')
  })
})

describe('CITrustSettings', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/')
    trust = []
    perms = []
    gatePolicies = []
    overrides = []
    mockSaveTrust.mockReset()
    mockDeletePolicy.mockReset()
    mockRevokeOverride.mockReset()
  })

  it('a policy can block dependency vulnerabilities only when a fix exists', async () => {
    perms = ['scans:ci:read', 'scans:ci:policy']
    gatePolicies = [
      {
        id: 'gp1',
        scope_type: 'tenant',
        mode: 'enforce',
        fail_on_severity: 'high',
        fixable_only: true,
      },
    ]
    mockSavePolicy.mockReset()
    mockSavePolicy.mockResolvedValue(undefined)
    render(<CITrustSettings />)
    await userEvent.click(screen.getByRole('tab', { name: /gate policy/i }))
    expect(
      screen.getByText('Vulnerabilities without a fix: listed, not blocking (KEV still fails)')
    ).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /^edit/i }))
    const dialog = await screen.findByRole('dialog')
    const toggle = within(dialog).getByRole('switch', {
      name: 'Dependency and image vulnerabilities block only when a fix exists',
    })
    expect(toggle).toBeChecked()
    await userEvent.click(toggle)
    await userEvent.click(within(dialog).getByRole('button', { name: /^save/i }))
    expect(mockSavePolicy).toHaveBeenCalledWith(
      expect.objectContaining({
        body: expect.objectContaining({
          fixable_only: false,
          // Locks and the baseline settings travel with every write.
          locked_fields: [],
          baseline_secrets_block: true,
        }),
      })
    )
    // The dialog is large (a lock per field): role queries are slow on a busy runner.
  }, 15_000)

  it('deleting a repository gate policy asks first', async () => {
    perms = ['scans:ci:read', 'scans:ci:policy']
    gatePolicies = [{ id: 'gp1', scope_type: 'repository', scope_id: 'repo-9', mode: 'enforce' }]
    mockDeletePolicy.mockResolvedValue(undefined)
    render(<CITrustSettings />)
    await userEvent.click(screen.getByRole('tab', { name: /gate policy/i }))
    await userEvent.click(
      screen.getByRole('button', { name: 'Delete the policy for Repository repo-9' })
    )
    expect(mockDeletePolicy).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete the gate policy for Repository repo-9?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    expect(mockDeletePolicy).toHaveBeenCalledWith('gp1')
  })

  it('revoking a break-glass override asks first', async () => {
    perms = ['scans:ci:read', 'scans:ci:override']
    overrides = [
      {
        id: 'ov1',
        commit_sha: 'abcdef1234567890',
        active: true,
        reason: 'hotfix',
        repository_asset_id: 'repo-9',
        expires_at: '2026-12-01T00:00:00Z',
      },
    ]
    mockRevokeOverride.mockResolvedValue(undefined)
    render(<CITrustSettings />)
    await userEvent.click(screen.getByRole('tab', { name: /break-glass/i }))
    await userEvent.click(screen.getByRole('button', { name: 'Revoke' }))
    expect(mockRevokeOverride).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent(/Revoke the override for commit abcdef1/)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }))
    expect(mockRevokeOverride).toHaveBeenCalledWith('ov1')
  })

  it('says when pipelines may still use the old audience, and until when', () => {
    trust = [
      {
        id: 'old',
        name: 'GitHub acme',
        provider: 'github',
        issuer: 'https://token.actions.githubusercontent.com',
        audience: 'openctem:tenant:t-123',
        legacy_audience: 'https://openctem.example.com',
        legacy_audience_until: '2027-01-12T00:00:00Z',
        enabled: true,
        rules: { owners: ['acme'] },
      },
    ]
    render(<CITrustSettings />)
    expect(screen.getByTestId('ci-legacy-audience')).toHaveTextContent(
      'https://openctem.example.com'
    )
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
    expect(await screen.findByTestId('ci-snippet')).toHaveTextContent('tenant-id: t-123')
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

  it('saves a GitHub Enterprise Server issuer, and leaves github.com as the default', async () => {
    perms = ['scans:ci:read', 'scans:ci:write']
    render(<CITrustSettings />)
    await userEvent.click(screen.getByRole('button', { name: /add trust/i }))
    await userEvent.type(screen.getByLabelText('Name'), 'GHES')
    await userEvent.type(screen.getByLabelText('Owners'), 'acme')
    await userEvent.type(
      screen.getByLabelText(/github enterprise issuer/i),
      'https://github.example.com/_services/token'
    )
    mockSaveTrust.mockResolvedValue({
      id: 'c9',
      name: 'GHES',
      provider: 'github',
      audience: 'openctem:tenant:t-123',
    })
    await userEvent.click(screen.getByRole('button', { name: /^add$/i }))
    expect(mockSaveTrust).toHaveBeenCalledWith({
      id: undefined,
      body: expect.objectContaining({ issuer: 'https://github.example.com/_services/token' }),
    })
  })

  it('admits only the central workflow when pipeline definitions are listed', async () => {
    perms = ['scans:ci:read', 'scans:ci:write']
    render(<CITrustSettings />)
    await userEvent.click(screen.getByRole('button', { name: /add trust/i }))
    await userEvent.type(screen.getByLabelText('Name'), 'GitHub org')
    await userEvent.type(screen.getByLabelText('Owners'), 'acme')
    await userEvent.type(
      screen.getByLabelText('Pipeline definitions'),
      'acme/security/.github/workflows/scan.yml@refs/heads/main'
    )
    mockSaveTrust.mockResolvedValue({
      id: 'c3',
      name: 'GitHub org',
      provider: 'github',
      audience: 'openctem:tenant:t-123',
      rules: {
        owners: ['acme'],
        workflow_refs: ['acme/security/.github/workflows/scan.yml@refs/heads/main'],
      },
    })
    await userEvent.click(screen.getByRole('button', { name: /^add$/i }))
    expect(mockSaveTrust).toHaveBeenCalledWith({
      id: undefined,
      body: expect.objectContaining({
        rules: expect.objectContaining({
          workflow_refs: ['acme/security/.github/workflows/scan.yml@refs/heads/main'],
        }),
      }),
    })
    // The snippet says where the steps belong.
    expect(await screen.findByTestId('ci-snippet-workflow-refs')).toHaveTextContent(
      'acme/security/.github/workflows/scan.yml@refs/heads/main'
    )
  })

  it('offers pipeline definitions only where the token names them', async () => {
    perms = ['scans:ci:read', 'scans:ci:write']
    render(<CITrustSettings />)
    await userEvent.click(screen.getByRole('button', { name: /add trust/i }))
    expect(screen.getByLabelText('Pipeline definitions')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('combobox', { name: /provider/i }))
    await userEvent.click(await screen.findByRole('option', { name: 'Jenkins' }))
    expect(screen.queryByLabelText('Pipeline definitions')).not.toBeInTheDocument()
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
