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

export function snippetFor(provider: CIProvider, input: SnippetInput): string {
  return provider === 'gitlab' ? gitlabSnippet(input) : githubSnippet(input)
}

export const PROVIDER_LABEL: Record<string, string> = {
  github: 'GitHub Actions',
  gitlab: 'GitLab CI',
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
