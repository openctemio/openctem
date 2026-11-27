import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CIRunsView } from '../components/ci-runs-view'
import { ApiClientError } from '@/lib/api/error-handler'
import { CIConnections } from '../components/ci-connections'
import { CIGateSettings } from '../components/ci-gate-settings'
import { CIOverrides } from '../components/ci-overrides'
import { CISetupEntry } from '../components/ci-setup-wizard'
import { CIRefusalNotice, recentRefusals } from '../components/ci-refusals'
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
  CI_RELEASE_FALLBACK,
  ciRelease,
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
let refusals: unknown[] = []
let pipelines: unknown[] = []
const mockDeletePolicy = vi.fn()
const mockDeleteTrust = vi.fn()
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
  useCIRunnerRelease: () => undefined,
  useSaveCISettings: () => ({ trigger: mockSaveSettings, isMutating: false }),
  useSaveTrustConfig: () => ({ trigger: mockSaveTrust, isMutating: false }),
  useDeleteTrustConfig: () => ({ trigger: mockDeleteTrust, isMutating: false }),
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
  useTrustRefusals: () => ({ data: { data: refusals }, isLoading: false, mutate: vi.fn() }),
  useSCMApps: () => ({ data: { data: [], gitlab: [] }, isLoading: false, mutate: vi.fn() }),
  useCIPipelines: () => ({ data: { data: pipelines }, isLoading: false }),
}))

// Repository names (one list request in the app): asset id -> name.
const assetNames: Record<string, string> = { 'repo-9': 'github.com/acme/api' }
vi.mock('@/features/threat-model/hooks/use-threat-model-refs', () => ({
  useAssetNameMap: () => ({
    nameFor: (id?: string) => (id ? (assetNames[id] ?? id) : ''),
    isLoading: false,
  }),
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

/** The list's body rows (DataTable), without the header row. */
function runRows(): HTMLElement[] {
  return screen.getAllByRole('row').filter((r) => within(r).queryAllByRole('cell').length > 0)
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
    expect(gh).toContain(`uses: openctemio/ci/.github/workflows/scan.yml@${CI_RELEASE_FALLBACK}`)
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
    expect(gl).toContain(`openctemio/ci/${CI_RELEASE_FALLBACK}/gitlab/templates/all.yml`)
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
      expect(s).toContain(`ghcr.io/openctemio/ci:${CI_RELEASE_FALLBACK}`)
    }
    for (const p of CI_PROVIDERS) expect(snippetFor(p, input)).not.toContain('ci:edge')
  })

  it('pins the API-supplied CI runner release, and only a vX.Y.Z one', () => {
    const input = {
      apiUrl: 'https://ctem.example',
      tenantId: 't1',
      audience: defaultAudience('t1'),
      release: 'v0.9.2',
    }
    expect(githubSnippet(input)).toContain('uses: openctemio/ci/.github/workflows/scan.yml@v0.9.2')
    expect(githubSnippet(input)).toContain('required by openctemio/ci v0.9.2')
    expect(gitlabSnippet(input)).toContain('openctemio/ci/v0.9.2/gitlab/templates/all.yml')
    for (const p of ['azure_devops', 'bitbucket', 'circleci'] as const) {
      expect(snippetFor(p, input)).toContain('ghcr.io/openctemio/ci:v0.9.2')
    }
    // No release from the API, or anything that is not a release, takes the
    // built-in fallback: the value is written into pipeline YAML and URLs.
    expect(ciRelease(undefined)).toBe(CI_RELEASE_FALLBACK)
    for (const bad of ['', 'latest', 'v1.2', 'v1.2.3-rc.1', 'v1.2.3\nrun: evil', '../main']) {
      expect(ciRelease(bad)).toBe(CI_RELEASE_FALLBACK)
      expect(githubSnippet({ ...input, release: bad })).toContain(`scan.yml@${CI_RELEASE_FALLBACK}`)
    }
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
    expect(screen.getByRole('button', { name: /connect a ci provider/i })).toBeInTheDocument()
    perms = []
  })

  it('tells a reader the runs they see follow their access, not that none exist', () => {
    perms = []
    render(<CIRunsView />)
    expect(screen.getByText('No CI runs you can see')).toBeInTheDocument()
    expect(screen.queryByText('No CI runs yet')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /connect a ci provider/i })).not.toBeInTheDocument()
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
    const [row] = runRows()
    // The code host is dropped from the path; the provider is the icon.
    expect(within(row).getByText('acme/api')).toBeInTheDocument()
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
    expect(lastRunFilters).toEqual({ verdict: '', page: 1, perPage: 25 })
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
    // The run's repository is picked already, by name (the id stays internal).
    expect(screen.getByTestId('ci-repository-picked')).toHaveTextContent('asset-1')
    expect(screen.queryByLabelText('Repository asset ID')).not.toBeInTheDocument()
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
    const rows = runRows()
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

  it('puts why the run failed before its details', async () => {
    runDetail = judgedRun
    window.history.replaceState({}, '', '/ci-cd?view=runs&run=r2')
    render(<CIRunsView />)
    const blocking = await screen.findByRole('list', { name: 'Blocking' })
    const details = screen.getByRole('heading', { name: 'Details' })
    // Blocking comes first in the document (a developer opens the run to see why).
    expect(
      blocking.compareDocumentPosition(details) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy()
    const summary = screen.getByText(/2 findings judged/)
    expect(
      summary.compareDocumentPosition(blocking) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy()
  })

  it('keeps the open run in the URL', async () => {
    runs = [failingRun]
    runDetail = { ...failingRun }
    render(<CIRunsView />)
    await userEvent.click(runRows()[0])
    expect(window.location.search).toContain('run=r1')
  })
})

describe('Refused pipelines notice (Pipelines tab)', () => {
  const day = 86_400_000
  const at = (daysAgo: number) => new Date(Date.now() - daysAgo * day).toISOString()

  it('counts refusals of the last seven days only', () => {
    const now = Date.parse('2026-10-31T00:00:00Z')
    const list = [
      { at: '2026-10-30T00:00:00Z' },
      { at: '2026-10-24T00:00:00Z' },
      { at: '2026-10-23T23:59:00Z' },
      { at: undefined },
    ]
    expect(recentRefusals(list, now)).toHaveLength(2)
  })

  it('tells a CI writer how many pipelines were refused and links to why', () => {
    refusals = [{ at: at(1) }, { at: at(2) }, { at: at(30) }]
    render(<CIRefusalNotice canWrite />)
    expect(screen.getByTestId('ci-refusal-notice')).toHaveTextContent(
      '2 pipelines were refused in the last 7 days.'
    )
    expect(screen.getByRole('link', { name: /see why/i })).toHaveAttribute(
      'href',
      '/ci-cd?tab=connections&refused=1'
    )
    refusals = []
  })

  it('says nothing to a reader, or when nothing was refused lately', () => {
    refusals = [{ at: at(1) }]
    const { container, unmount } = render(<CIRefusalNotice canWrite={false} />)
    expect(container).toBeEmptyDOMElement()
    unmount()
    refusals = [{ at: at(40) }]
    const second = render(<CIRefusalNotice canWrite />)
    expect(second.container).toBeEmptyDOMElement()
    refusals = []
  })
})

const ghTrust = {
  id: 'old',
  name: 'GitHub acme',
  provider: 'github',
  issuer: 'https://token.actions.githubusercontent.com',
  audience: 'openctem:tenant:t-123',
  enabled: true,
  last_used_at: '2026-10-05T10:00:00Z',
  rules: { owners: ['acme'] },
}

/** Opens the full rules form the way a person does: Connect a CI provider, then every rule. */
async function openEveryRule() {
  render(<CISetupEntry canWrite />)
  await userEvent.click(screen.getByRole('button', { name: 'Connect a CI provider' }))
  await userEvent.click(await screen.findByRole('button', { name: 'Fill in every rule yourself' }))
  return screen.findByRole('dialog')
}

describe('CIConnections (Connections tab)', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/ci-cd?tab=connections')
    trust = []
    perms = ['scans:ci:read', 'scans:ci:write']
    refusals = []
    ciSettings = { require_oidc: true }
    mockDeleteTrust.mockReset()
    mockSaveTrust.mockReset()
  })

  it('opens with one status line, then one line per configuration, no section headings', () => {
    trust = [
      ghTrust,
      { ...ghTrust, id: 'b', name: 'GitLab platform', provider: 'gitlab', last_used_at: undefined },
    ]
    refusals = [
      {
        at: new Date().toISOString(),
        repository: 'acme/x',
        provider: 'github',
        reasons: ['owner_not_allowed'],
      },
    ]
    render(<CIConnections />)
    const status = screen.getByTestId('ci-connections-status')
    expect(status).toHaveTextContent('1 connection working')
    expect(status).toHaveTextContent('last accepted job')
    expect(
      within(status).getByRole('button', { name: '1 job refused: see why' })
    ).toBeInTheDocument()
    expect(screen.getAllByTestId('ci-trust-row')).toHaveLength(2)
    expect(screen.queryAllByRole('heading', { level: 2 })).toHaveLength(0)
    // One main action lives in the page header: the tab adds none of its own.
    expect(screen.queryByRole('button', { name: /add trust/i })).not.toBeInTheDocument()
    // A row carries no buttons of its own: it opens the sheet.
    expect(screen.queryByRole('button', { name: 'Pipeline snippet' })).not.toBeInTheDocument()
  })

  it('keeps the provider icon inline with the name and the refused count on one line', () => {
    trust = [{ ...ghTrust, name: 'GitHub, a very long configuration name for the mobile team' }]
    refusals = [
      {
        at: new Date().toISOString(),
        repository: 'acme/x',
        provider: 'github',
        reasons: ['owner_not_allowed'],
      },
    ]
    render(<CIConnections />)
    const title = screen.getByTestId('ci-trust-title')
    // One flex row: the icon cannot drop onto its own line above a wrapping name.
    expect(title).toHaveClass('flex', 'items-start')
    expect(screen.getByTestId('ci-trust-icon')).toHaveClass('shrink-0', 'h-6')
    expect(screen.getByTestId('ci-trust-name')).toHaveClass('min-w-0')
    // The count never splits inside itself; the "last accepted" text wraps instead.
    expect(screen.getByTestId('ci-trust-refused')).toHaveClass('whitespace-nowrap', 'shrink-0')
  })

  it('opens a configuration in a sheet with Health, Rules, Scope and the snippet', async () => {
    trust = [ghTrust]
    render(<CIConnections />)
    await userEvent.click(screen.getByRole('button', { name: /^GitHub acme/ }))
    expect(window.location.search).toContain('connection=old')
    const tabs = screen.getAllByRole('tab').map((t) => t.textContent)
    expect(tabs).toEqual(['Health', 'Rules', 'Scope', 'Pipeline snippet'])
    expect(screen.getByTestId('ci-sheet-last-accepted')).toHaveTextContent('Last accepted job')
    await userEvent.click(screen.getByRole('tab', { name: 'Pipeline snippet' }))
    expect(screen.getByTestId('ci-snippet')).toHaveTextContent('tenant-id: t-123')
    await userEvent.click(screen.getByRole('tab', { name: 'Rules' }))
    expect(screen.getByTestId('ci-trust-rules')).toBeInTheDocument()
    expect(screen.getByLabelText('Owners')).toHaveValue('acme')
  })

  it('a fix on a refused job opens Rules with the change filled in, saved only by Save', async () => {
    trust = [ghTrust]
    refusals = [
      {
        at: new Date().toISOString(),
        repository: 'acme/web',
        provider: 'github',
        ref: 'refs/heads/dev',
        reasons: ['ref_not_allowed'],
      },
    ]
    render(<CIConnections />)
    await userEvent.click(screen.getByRole('button', { name: /^GitHub acme/ }))
    const fixes = within(screen.getByTestId('ci-health-refusals')).getAllByRole('button')
    await userEvent.click(fixes[0])
    expect(screen.getByRole('tab', { name: 'Rules', selected: true })).toBeInTheDocument()
    expect(screen.getByTestId('ci-fix-note')).toBeInTheDocument()
    expect(mockSaveTrust).not.toHaveBeenCalled()
  })

  it('"see why" lists every recent refused job in a sheet', async () => {
    trust = [ghTrust]
    refusals = Array.from({ length: 5 }, (_, i) => ({
      at: new Date(Date.now() - i * 60_000).toISOString(),
      repository: `acme/r${i}`,
      provider: 'github',
      reasons: ['owner_not_allowed'],
    }))
    render(<CIConnections />)
    await userEvent.click(screen.getByRole('button', { name: '5 jobs refused: see why' }))
    expect(window.location.search).toContain('refused=1')
    expect(await screen.findAllByTestId('ci-refusal')).toHaveLength(5)
  })

  it('deleting a configuration from its sheet asks for its name first', async () => {
    trust = [ghTrust]
    mockDeleteTrust.mockResolvedValue(undefined)
    render(<CIConnections />)
    await userEvent.click(screen.getByRole('button', { name: /^GitHub acme/ }))
    await userEvent.click(screen.getByRole('button', { name: 'More actions' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Delete GitHub acme' }))
    expect(mockDeleteTrust).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete the CI trust "GitHub acme"?')
    const confirm = within(dialog).getByRole('button', { name: 'Delete CI trust' })
    expect(confirm).toBeDisabled()
    await userEvent.type(within(dialog).getByRole('textbox'), 'GitHub acme')
    await userEvent.click(confirm)
    expect(mockDeleteTrust).toHaveBeenCalledWith('old')
  })

  it('a reader sees the rules as text, with no editor and no delete', async () => {
    perms = ['scans:ci:read']
    trust = [ghTrust]
    render(<CIConnections />)
    expect(screen.queryByTestId('ci-connections-see-why')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /^GitHub acme/ }))
    expect(screen.queryByRole('button', { name: 'More actions' })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Rules' }))
    expect(screen.queryByTestId('ci-trust-rules')).not.toBeInTheDocument()
    expect(screen.getByText('owners acme')).toBeInTheDocument()
  })

  it('says when pipelines may still use the old audience, and until when (Health)', async () => {
    trust = [
      {
        ...ghTrust,
        legacy_audience: 'https://openctem.example.com',
        legacy_audience_until: '2027-01-12T00:00:00Z',
      },
    ]
    render(<CIConnections />)
    await userEvent.click(screen.getByRole('button', { name: /^GitHub acme/ }))
    const text = screen.getByTestId('ci-legacy-audience').textContent ?? ''
    expect(text).toContain('https://openctem.example.com')
    expect(text).toContain('Jan 12, 2027')
    expect(text.match(/until/gi)).toBeNull()
  })

  it('folds Require OIDC under Organization rules, its state in the summary', async () => {
    ciSettings = { require_oidc: true }
    render(<CIConnections />)
    const fold = screen.getByRole('button', { name: /organization rules/i })
    expect(fold).toHaveTextContent('(Require OIDC for CI results: on)')
    expect(screen.queryByTestId('ci-require-oidc-on')).not.toBeInTheDocument()
    await userEvent.click(fold)
    expect(screen.getByTestId('ci-require-oidc-on')).toHaveTextContent(
      'CI jobs must use their OIDC identity'
    )
  })

  it('lets an administrator require OIDC from the fold while CI sensor keys are accepted', async () => {
    ciSettings = { require_oidc: false }
    mockSaveSettings.mockResolvedValue({ require_oidc: true })
    render(<CIConnections />)
    await userEvent.click(screen.getByRole('button', { name: /organization rules/i }))
    expect(screen.getByTestId('ci-require-oidc-banner')).toHaveTextContent(/still accepted/i)
    await userEvent.click(screen.getByLabelText('Require OIDC for CI'))
    expect(mockSaveSettings).toHaveBeenCalledWith({ require_oidc: true })
    ciSettings = { require_oidc: true }
  })

  it('a member cannot change Require OIDC', async () => {
    perms = ['scans:ci:read']
    render(<CIConnections />)
    await userEvent.click(screen.getByRole('button', { name: /organization rules/i }))
    expect(screen.getByLabelText('Require OIDC for CI')).toBeDisabled()
  })
})

describe('CIGateSettings (Gate tab)', () => {
  beforeEach(() => {
    perms = ['scans:ci:read', 'scans:ci:policy']
    gatePolicies = []
    pipelines = []
    mockDeletePolicy.mockReset()
    mockSavePolicy.mockReset()
  })

  it('a policy can block dependency vulnerabilities only when a fix exists', async () => {
    gatePolicies = [
      {
        id: 'gp1',
        scope_type: 'tenant',
        mode: 'enforce',
        fail_on_severity: 'high',
        fixable_only: true,
      },
    ]
    mockSavePolicy.mockResolvedValue(undefined)
    render(<CIGateSettings />)
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
          locked_fields: [],
          baseline_secrets_block: true,
        }),
      })
    )
  }, 15_000)

  it('names a repository policy by the repository, never its id, and asks before deleting', async () => {
    gatePolicies = [{ id: 'gp1', scope_type: 'repository', scope_id: 'repo-9', mode: 'enforce' }]
    mockDeletePolicy.mockResolvedValue(undefined)
    render(<CIGateSettings />)
    expect(screen.getByText('Repository github.com/acme/api')).toBeInTheDocument()
    expect(screen.queryByText(/repo-9/)).not.toBeInTheDocument()
    await userEvent.click(
      screen.getByRole('button', { name: 'Delete the policy for Repository github.com/acme/api' })
    )
    const dialog = await screen.findByRole('alertdialog')
    const confirm = within(dialog).getByRole('button', { name: 'Delete gate policy' })
    expect(confirm).toBeDisabled()
    await userEvent.type(
      within(dialog).getByLabelText(/Type Repository github.com\/acme\/api to confirm/),
      'Repository github.com/acme/api'
    )
    await userEvent.click(confirm)
    expect(mockDeletePolicy).toHaveBeenCalledWith({ id: 'gp1', reason: '' })
  })

  it('picks the repository of a new policy by name and sends its id', async () => {
    pipelines = [
      { id: 'p1', repository: 'github.com/acme/api', repository_asset_id: 'repo-9' },
      { id: 'p2', repository: 'github.com/acme/api', repository_asset_id: 'repo-9' },
    ]
    mockSavePolicy.mockResolvedValue(undefined)
    render(<CIGateSettings />)
    await userEvent.click(
      screen.getByRole('button', { name: 'Add a business unit or repository policy' })
    )
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByLabelText(/asset id/i)).not.toBeInTheDocument()
    await userEvent.type(within(dialog).getByLabelText('Repository'), 'acme')
    const choices = await within(dialog).findByTestId(
      'ci-repository-choices',
      {},
      { timeout: 2000 }
    )
    // One entry per repository, however many pipelines it runs.
    expect(within(choices).getAllByRole('button')).toHaveLength(1)
    await userEvent.click(within(choices).getByRole('button', { name: 'github.com/acme/api' }))
    expect(within(dialog).getByTestId('ci-repository-picked')).toHaveTextContent(
      'github.com/acme/api'
    )
  })
})

describe('CIOverrides (break-glass on Runs)', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/ci-cd?view=runs')
    overrides = []
    mockRevokeOverride.mockReset()
  })

  const active = {
    id: 'ov1',
    commit_sha: 'abcdef1234567890',
    active: true,
    reason: 'hotfix',
    repository_asset_id: 'repo-9',
    expires_at: '2026-12-01T00:00:00Z',
  }

  it('revoking an override asks first, and names the repository', async () => {
    perms = ['scans:ci:read', 'scans:ci:override']
    overrides = [active]
    mockRevokeOverride.mockResolvedValue(undefined)
    render(<CIOverrides canOverride />)
    // The Runs tab reads only its runs on load: the overrides come on request.
    await userEvent.click(screen.getByRole('button', { name: 'Show overrides' }))
    expect(screen.getByTestId('ci-overrides')).toHaveTextContent('github.com/acme/api, until')
    expect(screen.getByTestId('ci-overrides')).not.toHaveTextContent('repo-9')
    await userEvent.click(screen.getByRole('button', { name: 'Revoke' }))
    expect(mockRevokeOverride).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent(/Revoke the override for commit abcdef1/)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }))
    expect(mockRevokeOverride).toHaveBeenCalledWith('ov1')
  })

  it('folds past overrides behind one button', async () => {
    overrides = [{ ...active, id: 'ov2', active: false, revoked_at: '2026-10-01T00:00:00Z' }]
    render(<CIOverrides canOverride />)
    await userEvent.click(screen.getByRole('button', { name: 'Show overrides' }))
    expect(screen.getByTestId('ci-overrides-none-active')).toBeInTheDocument()
    expect(screen.queryByTestId('ci-overrides')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Show 1 past overrides' }))
    expect(screen.getByTestId('ci-overrides')).toHaveTextContent('Revoked')
  })

  it('a member cannot override a commit', () => {
    render(<CIOverrides canOverride={false} />)
    expect(screen.getByRole('button', { name: 'Override a commit' })).toBeDisabled()
  })

  it('scrolls to itself for an old ?section=break-glass link', () => {
    const scrolled: string[] = []
    const spy = vi.spyOn(Element.prototype, 'scrollIntoView').mockImplementation(function (
      this: Element
    ) {
      scrolled.push(this.id)
    })
    window.history.replaceState({}, '', '/ci-cd?view=runs&section=break-glass')
    render(<CIOverrides canOverride />)
    expect(scrolled).toEqual(['ci-setup-break-glass'])
    // The link opens the overrides at once.
    expect(screen.queryByRole('button', { name: 'Show overrides' })).not.toBeInTheDocument()
    spy.mockRestore()
  })
})

describe('Every rule (the full form, from Connect a CI provider)', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/')
    trust = []
    perms = ['scans:ci:read', 'scans:ci:write']
    mockSaveTrust.mockReset()
  })

  it('refuses a configuration that names no owner or repository, then shows the snippet', async () => {
    const dialog = await openEveryRule()
    await userEvent.type(within(dialog).getByLabelText('Name'), 'GitHub org')
    const add = within(dialog).getByRole('button', { name: /^add$/i })
    expect(add).toBeDisabled()
    await userEvent.type(within(dialog).getByLabelText('Owners'), 'acme')
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
    expect(await screen.findByTestId('ci-snippet')).toHaveTextContent('tenant-id: t-123')
  })

  it('every list field says it takes several values', async () => {
    await openEveryRule()
    await userEvent.click(screen.getByRole('button', { name: /more rules/i }))
    const several = 'Several values: separate them with commas.'
    for (const label of ['Owners', 'Repositories', 'Branches and tags', 'Environments', 'Events']) {
      const hint = screen.getByLabelText(label).parentElement?.querySelector('p')
      expect(hint?.textContent, label).toContain(several)
    }
    expect(screen.getByLabelText('Owners')).toHaveAttribute('placeholder', 'acme, acme-labs')
  })

  it('warns before admitting fork pull requests', async () => {
    await openEveryRule()
    await userEvent.click(screen.getByRole('button', { name: /more rules/i }))
    await userEvent.click(screen.getByLabelText('Admit fork pull requests'))
    expect(screen.getByText(/fork code would act/i)).toBeInTheDocument()
  })

  it('saves a GitHub Enterprise Server issuer, and leaves github.com as the default', async () => {
    await openEveryRule()
    await userEvent.type(screen.getByLabelText('Name'), 'GHES')
    await userEvent.type(screen.getByLabelText('Owners'), 'acme')
    await userEvent.type(
      screen.getByLabelText(/github enterprise issuer/i),
      'https://github.example.com/_services/token'
    )
    mockSaveTrust.mockResolvedValue({ id: 'c9', name: 'GHES', provider: 'github' })
    await userEvent.click(screen.getByRole('button', { name: /^add$/i }))
    expect(mockSaveTrust).toHaveBeenCalledWith({
      id: undefined,
      body: expect.objectContaining({ issuer: 'https://github.example.com/_services/token' }),
    })
  })

  it('saves pasted signing keys, and refuses to save a document with a private key', async () => {
    await openEveryRule()
    await userEvent.type(screen.getByLabelText('Name'), 'Self-managed')
    await userEvent.type(screen.getByLabelText('Owners'), 'acme')
    const add = screen.getByRole('button', { name: /^add$/i })
    await userEvent.click(screen.getByRole('radio', { name: 'Use keys I paste' }))
    // Pasted mode without keys cannot be saved.
    expect(add).toBeDisabled()
    const key = {
      kty: 'EC',
      kid: 'gitlab-k1',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    }
    const box = screen.getByLabelText('Keys (JWKS document)')
    await userEvent.click(box)
    await userEvent.paste(JSON.stringify({ keys: [{ ...key, d: 'c2VjcmV0' }] }))
    expect(screen.getByTestId('ci-signing-keys-error')).toBeInTheDocument()
    expect(add).toBeDisabled()
    await userEvent.clear(box)
    const pasted = JSON.stringify({ keys: [key] })
    await userEvent.click(box)
    await userEvent.paste(pasted)
    expect(add).toBeEnabled()
    mockSaveTrust.mockResolvedValue({
      id: 'c10',
      name: 'Self-managed',
      provider: 'github',
      audience: 'openctem:tenant:t-123',
    })
    await userEvent.click(add)
    expect(mockSaveTrust).toHaveBeenCalledWith({
      id: undefined,
      body: expect.objectContaining({ key_source: 'pasted', signing_keys: pasted }),
    })
  })

  it('shows the pasted kids and the last used key on the connection health', async () => {
    trust = [
      {
        id: 'c11',
        name: 'Self-managed',
        provider: 'gitlab',
        enabled: true,
        rules: { owners: ['acme'] },
        key_source: 'pasted',
        signing_key_list: [{ kid: 'gitlab-k1', alg: 'RS256' }],
        signing_keys_updated_at: new Date().toISOString(),
        last_key_id: 'gitlab-k1',
      },
    ]
    render(<CIConnections />)
    await userEvent.click(screen.getByRole('button', { name: /Self-managed/ }))
    const summary = screen.getByTestId('ci-signing-keys-summary')
    expect(summary).toHaveTextContent('gitlab-k1 (RS256)')
    expect(summary).toHaveTextContent('Last used key gitlab-k1')
  })

  it('admits only the central workflow when pipeline definitions are listed', async () => {
    await openEveryRule()
    await userEvent.type(screen.getByLabelText('Name'), 'GitHub org')
    await userEvent.type(screen.getByLabelText('Owners'), 'acme')
    await userEvent.click(screen.getByRole('button', { name: /more rules/i }))
    await userEvent.type(
      screen.getByLabelText(/paste the value shown in a refusal/i),
      'acme/security/.github/workflows/scan.yml@refs/heads/main'
    )
    await userEvent.click(screen.getByRole('button', { name: /^add value$/i }))
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
    expect(await screen.findByTestId('ci-snippet-workflow-refs')).toHaveTextContent(
      'acme/security/.github/workflows/scan.yml@refs/heads/main'
    )
  })

  it('offers pipeline definitions only where the token names them', async () => {
    await openEveryRule()
    await userEvent.click(screen.getByRole('button', { name: /more rules/i }))
    expect(screen.getByTestId('ci-pipeline-definitions')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('combobox', { name: /provider/i }))
    await userEvent.click(await screen.findByRole('option', { name: 'Jenkins' }))
    expect(screen.queryByTestId('ci-pipeline-definitions')).not.toBeInTheDocument()
  })

  it('guides a Bitbucket trust: workspace, its UUID, repositories by UUID', async () => {
    await openEveryRule()
    await userEvent.click(screen.getByRole('combobox', { name: /provider/i }))
    await userEvent.click(await screen.findByRole('option', { name: 'Bitbucket Pipelines' }))
    expect(screen.queryByLabelText('Events')).not.toBeInTheDocument()
    expect(screen.getByText(/the token signs the id, never the name/i)).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('Name'), 'BB')
    await userEvent.type(screen.getByLabelText('Workspace'), 'acme')
    await userEvent.type(screen.getByLabelText('Workspace UUID'), 'ws-uuid')
    await userEvent.type(screen.getByLabelText('Owners'), 'acme')
    mockSaveTrust.mockResolvedValue({ id: 'c2', name: 'BB', provider: 'bitbucket' })
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
    await openEveryRule()
    await userEvent.click(screen.getByRole('combobox', { name: /provider/i }))
    await userEvent.click(await screen.findByRole('option', { name: 'Azure Pipelines' }))
    await userEvent.click(screen.getByRole('button', { name: /more rules/i }))
    expect(screen.getByTestId('ci-fixed-audience')).toHaveTextContent('api://AzureADTokenExchange')
    expect(screen.queryByLabelText('Audience')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Protected branches and tags only')).not.toBeInTheDocument()
    expect(screen.getByText(/cannot tell a fork/i)).toBeInTheDocument()
    expect(screen.queryByTestId('ci-trust-preview')).not.toBeInTheDocument()
  })

  it('checks a sample token against the draft and shows the outcome', async () => {
    mockPreview.mockResolvedValue({
      verified: true,
      expired: true,
      admitted: false,
      refusal: { code: 'repository_not_allowed', detail: 'repository "acme/web" is not listed' },
      normalized: { repository: 'acme/web', ref: 'refs/heads/main', commit_verified: true },
      claims: { iss: 'https://token.actions.githubusercontent.com' },
    })
    await openEveryRule()
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
    await openEveryRule()
    expect(screen.queryByText(/deployment branch rules/i)).not.toBeInTheDocument()
    await userEvent.click(screen.getByLabelText('Protected branches and tags only'))
    expect(screen.getByText(/deployment branch rules/i)).toBeInTheDocument()
  })

  it('a member has no way to add a configuration', () => {
    perms = ['scans:ci:read']
    render(<CISetupEntry canWrite={false} />)
    expect(screen.queryByRole('button', { name: 'Connect a CI provider' })).not.toBeInTheDocument()
  })
})
