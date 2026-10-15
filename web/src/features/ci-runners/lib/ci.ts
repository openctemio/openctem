/**
 * Pure helpers for the CI pages: list parsing, pipeline snippets and labels.
 * No secret ever appears in a snippet: the pipeline proves who it is with its
 * provider's OIDC token (api RFC-051).
 */

import { DEFAULT_BRAND } from '@/lib/brand'

import type { CIProvider, CITrustConfig } from '../types'

/** Splits a comma- or newline-separated list, trimmed and de-duplicated. */
export function parseList(text: string): string[] {
  const out: string[] = []
  for (const raw of text.split(/[\n,]/)) {
    const v = raw.trim()
    if (v && !out.includes(v)) out.push(v)
  }
  return out
}

export function joinList(list: string[] | undefined): string {
  return (list ?? []).join(', ')
}

/** The audience the API gives a trust configuration created without one. */
export function defaultAudience(tenantId: string): string {
  return `openctem:tenant:${tenantId}`
}

export interface SnippetInput {
  apiUrl: string
  tenantId: string
  audience: string
  /** The branch push events scan (the trust's default branch); main if unset. */
  defaultBranch?: string
  /** The product name in job and stage names (the brand); OpenCTEM if unset. */
  productName?: string
}

/**
 * The openctemio/ci release the GitHub and GitLab snippets pin. A release tag
 * also pins the scanner images the workflow and templates run. Copied from
 * versions.yaml (ci.latest) by .github/scripts/release/sync-versions.sh:
 * change it there, never here.
 */
export const CI_RELEASE = 'v0.3.0'

/** The capabilities the GitHub and GitLab snippets run by default. */
const DEFAULT_CAPABILITIES = 'sast,sca,secrets,iac'

/**
 * A GitHub Actions workflow: the openctemio/ci reusable workflow runs one job
 * per capability in parallel, reports into one run with the job's OIDC token
 * and lets one gate job decide.
 */
export function githubSnippet({
  apiUrl,
  tenantId,
  audience,
  defaultBranch,
  productName = DEFAULT_BRAND.name,
}: SnippetInput): string {
  const audLine =
    audience && audience !== defaultAudience(tenantId) ? `\n      oidc-audience: ${audience}` : ''
  // The reusable workflow's scan job asks for security-events: write (needed
  // to upload SARIF), and GitHub refuses to start a called job that asks for
  // more than its caller grants, so the caller always grants it.
  const sarifLine = `\n      security-events: write # required by openctemio/ci ${CI_RELEASE}`
  return `name: ${productName}
on:
  pull_request:
  push:
    branches: [${yamlBranch(defaultBranch)}]

jobs:
  openctem:
    uses: openctemio/ci/.github/workflows/scan.yml@${CI_RELEASE}
    with:
      capabilities: ${DEFAULT_CAPABILITIES}
      api-url: ${apiUrl}
      tenant-id: ${tenantId}${audLine}
    permissions:
      contents: read
      id-token: write # the job asks GitHub for an OIDC token; no stored secret${sarifLine}
`
}

/** A branch name as a YAML flow-sequence item (quoted unless plainly safe). */
function yamlBranch(branch?: string): string {
  const b = (branch ?? '').trim() || 'main'
  return /^[A-Za-z0-9._/-]+$/.test(b) ? b : JSON.stringify(b)
}

/** Whether release a (vX.Y.Z) is older than release b. */
export function releaseBefore(a: string, b: string): boolean {
  const parse = (v: string) =>
    v
      .replace(/^v/, '')
      .split('.')
      .map((n) => Number.parseInt(n, 10) || 0)
  const [x, y] = [parse(a), parse(b)]
  for (let i = 0; i < 3; i++) {
    if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) < (y[i] ?? 0)
  }
  return false
}

const GITLAB_JOBS = [
  'openctem-sast',
  'openctem-sca',
  'openctem-secrets',
  'openctem-iac',
  'openctem-gate',
]

/**
 * A GitLab CI include of the openctemio/ci template: one job per capability
 * with the job's ID token, and one gate job. The template asks for the
 * default audience; a trust configuration with another audience gets each
 * job's id_tokens overridden.
 */
export function gitlabSnippet({ apiUrl, tenantId, audience }: SnippetInput): string {
  let override = ''
  if (audience && audience !== defaultAudience(tenantId)) {
    override =
      `\n# This trust configuration uses its own audience.\n.openctem-audience: &openctem-audience\n  id_tokens:\n    OPENCTEM_ID_TOKEN:\n      aud: ${audience}\n` +
      GITLAB_JOBS.map((j) => `${j}: *openctem-audience`).join('\n') +
      '\n'
  }
  return `include:
  - remote: https://raw.githubusercontent.com/openctemio/ci/${CI_RELEASE}/gitlab/templates/all.yml

variables:
  OPENCTEM_API_URL: ${apiUrl}
  OPENCTEM_TENANT_ID: ${tenantId} # jobs use their ID token; no stored secret
${override}`
}

// ─────────────────────────────────────────────── other CI systems ───

/**
 * The CI image that carries `openctem-ci`, at the release the other snippets
 * pin (never the moving edge build). Pin it by digest in a real pipeline (see
 * the openctemio/ci repository's docs/images.md).
 */
const CI_IMAGE = `ghcr.io/openctemio/ci:${CI_RELEASE}`

function ciEnv(apiUrl: string, tenantId: string, indent: string): string {
  return `${indent}OPENCTEM_API_URL: ${apiUrl}\n${indent}OPENCTEM_TENANT_ID: ${tenantId}`
}

/** An Azure Pipelines job: openctem-ci asks Azure DevOps for a pipeline token. */
export function azureSnippet({
  apiUrl,
  tenantId,
  productName = DEFAULT_BRAND.name,
}: SnippetInput): string {
  return `steps:
  - checkout: self
  - script: |
      docker run --rm -v "$(Build.SourcesDirectory):/src" -w /src \\
        -e SYSTEM_OIDCREQUESTURI -e SYSTEM_ACCESSTOKEN -e TF_BUILD \\
        -e BUILD_SOURCEVERSION -e BUILD_REPOSITORY_URI \\
        -e OPENCTEM_API_URL -e OPENCTEM_TENANT_ID \\
        ${CI_IMAGE} openctem-ci scan --capability sast
    displayName: ${productName} scan
    env:
      # The job's own access token, only to request its OIDC token; no stored secret.
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
${ciEnv(apiUrl, tenantId, '      ')}
`
}

/** A Bitbucket Pipelines step with an OIDC token for the platform's audience. */
export function bitbucketSnippet({
  apiUrl,
  tenantId,
  audience,
  productName = DEFAULT_BRAND.name,
}: SnippetInput): string {
  return `image: ${CI_IMAGE}

options:
  oidc:
    audiences:
      - ${audience}

pipelines:
  default:
    - step:
        name: ${productName} scan
        oidc: true # BITBUCKET_STEP_OIDC_TOKEN; no stored secret
        script:
          - export OPENCTEM_API_URL=${apiUrl} OPENCTEM_TENANT_ID=${tenantId}
          - openctem-ci scan --capability sast
`
}

/** A CircleCI job that mints a token for the platform's audience. */
export function circleciSnippet({
  apiUrl,
  tenantId,
  audience,
  productName = DEFAULT_BRAND.name,
}: SnippetInput): string {
  return `version: 2.1
jobs:
  openctem:
    docker:
      - image: ${CI_IMAGE}
    environment:
${ciEnv(apiUrl, tenantId, '      ')}
    steps:
      - checkout
      - run:
          name: ${productName} scan
          command: |
            # A token for this platform only; the default CIRCLE_OIDC_TOKEN is refused.
            export OPENCTEM_ID_TOKEN="$(circleci run oidc get --claims '{"aud":"${audience}"}')"
            openctem-ci scan --capability sast
`
}

/** A Jenkins stage that binds the OpenID Connect provider plugin's token. */
export function jenkinsSnippet({
  apiUrl,
  tenantId,
  productName = DEFAULT_BRAND.name,
}: SnippetInput): string {
  return `// Needs the OpenID Connect Provider plugin, its claim templates
// (repository, branch, sha) and an "OpenID Connect id token" credential
// whose audience is this trust configuration's.
stage('${productName} scan') {
  environment {
    OPENCTEM_API_URL = '${apiUrl}'
    OPENCTEM_TENANT_ID = '${tenantId}'
  }
  steps {
    withCredentials([string(credentialsId: 'openctem-oidc', variable: 'OPENCTEM_ID_TOKEN')]) {
      sh 'openctem-ci scan --capability sast'
    }
  }
}
`
}

export function snippetFor(provider: CIProvider, input: SnippetInput): string {
  switch (provider) {
    case 'gitlab':
      return gitlabSnippet(input)
    case 'azure_devops':
      return azureSnippet(input)
    case 'bitbucket':
      return bitbucketSnippet(input)
    case 'circleci':
      return circleciSnippet(input)
    case 'jenkins':
      return jenkinsSnippet(input)
    default:
      return githubSnippet(input)
  }
}

export const CI_PROVIDERS: CIProvider[] = [
  'github',
  'gitlab',
  'azure_devops',
  'bitbucket',
  'circleci',
  'jenkins',
]

export const PROVIDER_LABEL: Record<string, string> = {
  github: 'GitHub Actions',
  gitlab: 'GitLab CI',
  azure_devops: 'Azure Pipelines',
  bitbucket: 'Bitbucket Pipelines',
  circleci: 'CircleCI',
  jenkins: 'Jenkins',
}

/**
 * What each provider's token can prove, mirroring the API's checks (api
 * RFC-051 section 3.1): the form only shows rules a provider can back; the
 * API refuses the others anyway.
 */
export interface ProviderTraits {
  /** How the issuer is entered. */
  issuerInput: 'fixed' | 'url' | 'organization_id' | 'workspace'
  events: boolean
  environments: boolean
  /** How a protected ref is proven, if at all. */
  protectedRef: 'none' | 'claim' | 'environment'
  /** Repositories are listed by UUID (the token signs no name). */
  repositoriesById: boolean
  /** The only audience the provider issues. */
  fixedAudience?: string
  /** The audience must contain the organization id. */
  tenantAudience: boolean
  /** Pull request builds count as fork builds (the token cannot tell). */
  pullRequestsAsForks: boolean
  /** The token names the pipeline definition (workflow_refs rule). */
  workflowRefs: boolean
}

export const AZURE_DEVOPS_AUDIENCE = 'api://AzureADTokenExchange'

export const PROVIDER_TRAITS: Record<CIProvider, ProviderTraits> = {
  github: {
    issuerInput: 'fixed',
    events: true,
    environments: true,
    protectedRef: 'environment',
    repositoriesById: false,
    tenantAudience: false,
    pullRequestsAsForks: false,
    workflowRefs: true,
  },
  gitlab: {
    issuerInput: 'url',
    events: true,
    environments: true,
    protectedRef: 'claim',
    repositoriesById: false,
    tenantAudience: false,
    pullRequestsAsForks: false,
    workflowRefs: true,
  },
  azure_devops: {
    issuerInput: 'organization_id',
    events: false,
    environments: false,
    protectedRef: 'none',
    repositoriesById: false,
    fixedAudience: AZURE_DEVOPS_AUDIENCE,
    tenantAudience: false,
    pullRequestsAsForks: true,
    workflowRefs: false,
  },
  bitbucket: {
    issuerInput: 'workspace',
    events: false,
    environments: true,
    protectedRef: 'environment',
    repositoriesById: true,
    tenantAudience: true,
    pullRequestsAsForks: false,
    workflowRefs: false,
  },
  circleci: {
    issuerInput: 'organization_id',
    events: false,
    environments: false,
    protectedRef: 'none',
    repositoriesById: false,
    tenantAudience: true,
    pullRequestsAsForks: true,
    workflowRefs: false,
  },
  jenkins: {
    issuerInput: 'url',
    events: true,
    environments: true,
    protectedRef: 'none',
    repositoriesById: false,
    tenantAudience: true,
    pullRequestsAsForks: true,
    workflowRefs: false,
  },
}

const AZURE_ISSUER = 'https://vstoken.dev.azure.com/'
const CIRCLECI_ISSUER = 'https://oidc.circleci.com/org/'
const BITBUCKET_ISSUER =
  /^https:\/\/api\.bitbucket\.org\/2\.0\/workspaces\/([^/]+)\/pipelines-config\/identity\/oidc$/

/** The issuer for an organization id or workspace the administrator names. */
export function issuerFor(provider: CIProvider, value: string): string | undefined {
  const v = value.trim().toLowerCase()
  if (!v) return undefined
  switch (provider) {
    case 'azure_devops':
      return AZURE_ISSUER + v
    case 'circleci':
      return CIRCLECI_ISSUER + v
    case 'bitbucket':
      return `https://api.bitbucket.org/2.0/workspaces/${v}/pipelines-config/identity/oidc`
    default:
      return value.trim()
  }
}

/** The GitHub Actions issuer on github.com (the default). */
export const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com'

/** The issuer of a GitLab trust configuration left empty (gitlab.com). */
const GITLAB_COM = 'https://gitlab.com'

/**
 * An enabled trust configuration of this CI system and issuer that already
 * admits every owner (or repository) given, so the setup wizard reuses it
 * instead of creating a duplicate. Matching is case-insensitive, as owners are.
 */
export function findCoveringTrust(
  configs: CITrustConfig[],
  provider: CIProvider,
  issuerValue: string,
  scope: string[]
): CITrustConfig | undefined {
  if (scope.length === 0) return undefined
  const traits = PROVIDER_TRAITS[provider]
  let issuer: string | undefined
  if (traits.issuerInput !== 'fixed') {
    issuer = issuerFor(provider, issuerValue) ?? (provider === 'gitlab' ? GITLAB_COM : undefined)
    if (!issuer) return undefined
  }
  // The wizard connects github.com; an enterprise or server trust is another issuer.
  if (provider === 'github') issuer = GITHUB_ISSUER
  const norm = (v: string) => v.trim().toLowerCase().replace(/\/+$/, '')
  const want = scope.map(norm)
  return configs.find((c) => {
    if (c.provider !== provider || c.enabled === false) return false
    if (issuer && norm(c.issuer ?? '') !== norm(issuer)) return false
    const have = new Set(
      ((traits.repositoriesById ? c.rules?.repositories : c.rules?.owners) ?? []).map(norm)
    )
    return want.every((w) => have.has(w))
  })
}

/** The organization id or workspace an issuer names (to edit a configuration). */
export function organizationFromIssuer(provider: CIProvider, issuer: string | undefined): string {
  if (!issuer) return ''
  switch (provider) {
    case 'azure_devops':
      return issuer.startsWith(AZURE_ISSUER) ? issuer.slice(AZURE_ISSUER.length) : ''
    case 'circleci':
      return issuer.startsWith(CIRCLECI_ISSUER) ? issuer.slice(CIRCLECI_ISSUER.length) : ''
    case 'bitbucket':
      return BITBUCKET_ISSUER.exec(issuer)?.[1] ?? ''
    case 'github':
      // github.com is the default; only an enterprise or GitHub Enterprise
      // Server issuer is shown.
      return issuer === GITHUB_ISSUER ? '' : issuer
    default:
      return issuer
  }
}

/** A short commit id. */
export function shortSHA(sha?: string): string {
  return sha ? sha.slice(0, 8) : ''
}

/** Human label of a gate reason code. */
export const REASON_LABEL: Record<string, string> = {
  secret: 'Secret',
  kev: 'Known exploited',
  epss: 'EPSS',
  severity: 'Severity',
  scan_failure: 'Scan failure',
  missing_capability: 'Expected scan missing',
  capability_failed: 'Scan did not reach the platform',
  override: 'Break-glass',
  no_baseline: 'No baseline',
  secret_pre_existing: 'Secret already on the default branch',
  too_many_findings: 'Too many findings to judge',
  baseline_established: 'Baseline recorded',
  no_results: 'No results',
}

/** Reason codes that inform and never block (listed apart from the blocking ones). */
export const INFO_REASON_CODES = ['no_baseline', 'baseline_established', 'no_results']

export const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'none'] as const

/**
 * Refusal codes of a CI token exchange (api pkg/domain/cirun and the exchange
 * itself). Each has the i18n keys scans.ci.refusal.<code> (why) and
 * scans.ci.refusal.<code>Fix (how to fix); an unknown code shows as is.
 */
export const REFUSAL_CODES = [
  'no_matching_configuration',
  'missing_claims',
  'owner_not_allowed',
  'repository_not_allowed',
  'ref_not_allowed',
  'ref_not_protected',
  'environment_not_allowed',
  'event_not_allowed',
  'fork_pull_request',
  'workflow_not_allowed',
  'organization_mismatch',
  'owner_id_mismatch',
  'repository_binding',
  'pipeline_identity',
  'ssh_rerun',
  'replay',
  'runner_outdated',
  'pipeline_cap',
  'pipeline_rate',
  'run_mismatch',
  'aggregate_no_run_id',
  'legacy_audience',
] as const

export type RefusalCode = (typeof REFUSAL_CODES)[number]

/** Whether a code has translations. */
export function isKnownRefusal(code: string): code is RefusalCode {
  return (REFUSAL_CODES as readonly string[]).includes(code)
}
