/**
 * Pure helpers for the CI pages: list parsing, pipeline snippets and labels.
 * No secret ever appears in a snippet: the pipeline proves who it is with its
 * provider's OIDC token (api RFC-051).
 */

import type { CIProvider } from '../types'

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
  tools?: string
}

const DEFAULT_TOOLS = 'semgrep,betterleaks,trivy'

/** A GitHub Actions job that authenticates with the job's OIDC token. */
export function githubSnippet({
  apiUrl,
  tenantId,
  audience,
  tools = DEFAULT_TOOLS,
}: SnippetInput): string {
  const audLine =
    audience && audience !== defaultAudience(tenantId)
      ? `\n          OPENCTEM_OIDC_AUDIENCE: ${audience}`
      : ''
  return `permissions:
  contents: read
  id-token: write # the job asks GitHub for an OIDC token; no stored secret

jobs:
  openctem:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: OpenCTEM security scan
        uses: docker://ghcr.io/openctemio/sensor:latest-ci
        with:
          args: -tools ${tools} -target . -auto-ci -push
        env:
          API_URL: ${apiUrl}
          OPENCTEM_TENANT_ID: ${tenantId}${audLine}
`
}

/** A GitLab CI job that authenticates with the job's ID token. */
export function gitlabSnippet({
  apiUrl,
  tenantId,
  audience,
  tools = DEFAULT_TOOLS,
}: SnippetInput): string {
  return `openctem-security:
  image: ghcr.io/openctemio/sensor:latest-ci
  id_tokens:
    OPENCTEM_ID_TOKEN: # the job's ID token; no stored secret
      aud: ${audience}
  variables:
    API_URL: ${apiUrl}
    OPENCTEM_TENANT_ID: ${tenantId}
  script:
    - openctemio-sensor -tools ${tools} -target . -auto-ci -push
`
}

// ─────────────────────────────────────────────── other CI systems ───

/**
 * The CI image that carries `openctem-ci`. Pin a release by digest in a real
 * pipeline (see the openctemio/ci repository's docs/images.md).
 */
const CI_IMAGE = 'ghcr.io/openctemio/ci:edge'

function ciEnv(apiUrl: string, tenantId: string, indent: string): string {
  return `${indent}OPENCTEM_API_URL: ${apiUrl}\n${indent}OPENCTEM_TENANT_ID: ${tenantId}`
}

/** An Azure Pipelines job: openctem-ci asks Azure DevOps for a pipeline token. */
export function azureSnippet({ apiUrl, tenantId }: SnippetInput): string {
  return `steps:
  - checkout: self
  - script: |
      docker run --rm -v "$(Build.SourcesDirectory):/src" -w /src \\
        -e SYSTEM_OIDCREQUESTURI -e SYSTEM_ACCESSTOKEN -e TF_BUILD \\
        -e BUILD_SOURCEVERSION -e BUILD_REPOSITORY_URI \\
        -e OPENCTEM_API_URL -e OPENCTEM_TENANT_ID \\
        ${CI_IMAGE} openctem-ci scan --capability sast
    displayName: OpenCTEM scan
    env:
      # The job's own access token, only to request its OIDC token; no stored secret.
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
${ciEnv(apiUrl, tenantId, '      ')}
`
}

/** A Bitbucket Pipelines step with an OIDC token for the platform's audience. */
export function bitbucketSnippet({ apiUrl, tenantId, audience }: SnippetInput): string {
  return `image: ${CI_IMAGE}

options:
  oidc:
    audiences:
      - ${audience}

pipelines:
  default:
    - step:
        name: OpenCTEM scan
        oidc: true # BITBUCKET_STEP_OIDC_TOKEN; no stored secret
        script:
          - export OPENCTEM_API_URL=${apiUrl} OPENCTEM_TENANT_ID=${tenantId}
          - openctem-ci scan --capability sast
`
}

/** A CircleCI job that mints a token for the platform's audience. */
export function circleciSnippet({ apiUrl, tenantId, audience }: SnippetInput): string {
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
          name: OpenCTEM scan
          command: |
            # A token for this platform only; the default CIRCLE_OIDC_TOKEN is refused.
            export OPENCTEM_ID_TOKEN="$(circleci run oidc get --claims '{"aud":"${audience}"}')"
            openctem-ci scan --capability sast
`
}

/** A Jenkins stage that binds the OpenID Connect provider plugin's token. */
export function jenkinsSnippet({ apiUrl, tenantId }: SnippetInput): string {
  return `// Needs the OpenID Connect Provider plugin, its claim templates
// (repository, branch, sha) and an "OpenID Connect id token" credential
// whose audience is this trust configuration's.
stage('OpenCTEM scan') {
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
  },
  gitlab: {
    issuerInput: 'url',
    events: true,
    environments: true,
    protectedRef: 'claim',
    repositoriesById: false,
    tenantAudience: false,
    pullRequestsAsForks: false,
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
  },
  bitbucket: {
    issuerInput: 'workspace',
    events: false,
    environments: true,
    protectedRef: 'environment',
    repositoriesById: true,
    tenantAudience: true,
    pullRequestsAsForks: false,
  },
  circleci: {
    issuerInput: 'organization_id',
    events: false,
    environments: false,
    protectedRef: 'none',
    repositoriesById: false,
    tenantAudience: true,
    pullRequestsAsForks: true,
  },
  jenkins: {
    issuerInput: 'url',
    events: true,
    environments: true,
    protectedRef: 'none',
    repositoriesById: false,
    tenantAudience: true,
    pullRequestsAsForks: true,
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
  override: 'Break-glass',
  no_baseline: 'No baseline',
}

export const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'none'] as const
