/**
 * Helpers of the "Connect a CI provider" flow and of trust health (api
 * RFC-051): the issuer exactly as tokens carry it, the repository choice as
 * trust rules, pipeline definitions built from project + file + branch, the
 * cause of a failed signature check, and the fix a refused pipeline needs.
 * Rule semantics follow server/pkg/domain/cirun (Rules.Admit, repoMatch).
 */

import type { CIProvider, CITokenRefusal, CITrustConfig } from '../types'

/**
 * The issuer as it must appear in tokens: https, lower-case host, no
 * trailing slash, no query or fragment. Empty input stays empty (the
 * provider's default issuer applies). Anything that is not a host gives ''.
 */
export function normaliseIssuer(raw: string): string {
  let v = raw.trim()
  if (!v) return ''
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) v = `https://${v}`
  let u: URL
  try {
    u = new URL(v)
  } catch {
    return ''
  }
  if (!u.hostname || (u.protocol !== 'https:' && u.protocol !== 'http:')) return ''
  const path = u.pathname.replace(/\/+$/, '')
  return `https://${u.host.toLowerCase()}${path}`
}

/** The host part of an issuer ("gitlab.example.com"), '' when unreadable. */
export function issuerHost(issuer: string): string {
  try {
    return new URL(issuer).host.toLowerCase()
  } catch {
    return ''
  }
}

/** Whether an issuer names a private or local host (the platform may be unable to reach it). */
export function looksPrivate(issuer: string): boolean {
  const h = issuerHost(issuer).replace(/:\d+$/, '')
  if (!h) return false
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.lan'))
    return true
  const m = h.match(/^(\d+)\.(\d+)\.\d+\.\d+$/)
  if (!m) return false
  const [a, b] = [Number(m[1]), Number(m[2])]
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
}

/** Which repositories a new configuration admits. */
export type RepoChoice = 'group' | 'direct' | 'list'

/**
 * The owners and repositories rules of a repository choice. One
 * configuration covers any number of groups:
 * - group: every project in each group and its subgroups (a top-level group
 *   is an owner; a subgroup is `group/sub/**`);
 * - direct: projects directly in each group (`group/*`);
 * - list: exactly these projects.
 */
export function repoRules(
  choice: RepoChoice,
  groups: string[],
  projects: string[]
): { owners: string[]; repositories: string[] } {
  if (choice === 'list') return { owners: [], repositories: projects }
  const gs = groups.map((g) => g.trim().replace(/^\/+|\/+$/g, '')).filter(Boolean)
  if (choice === 'direct') return { owners: [], repositories: gs.map((g) => `${g}/*`) }
  return {
    owners: gs.filter((g) => !g.includes('/')),
    repositories: gs.filter((g) => g.includes('/')).map((g) => `${g}/**`),
  }
}

/** Which branches a new configuration admits. */
export type BranchChoice = 'protected' | 'default' | 'all'

/** The refs rule and protected switch of a branch choice. */
export function branchRules(
  choice: BranchChoice,
  defaultBranch: string
): { refs: string[]; require_protected_ref: boolean } {
  if (choice === 'protected') return { refs: [], require_protected_ref: true }
  if (choice === 'default')
    return { refs: [defaultBranch.trim() || 'main'], require_protected_ref: false }
  return { refs: [], require_protected_ref: false }
}

/**
 * The branch choices a provider supports, safest useful first. GitLab tokens say
 * whether a ref is protected; other tokens do not, and their pull request
 * builds run on the source branch, so every branch stays their default.
 */
export function branchChoices(provider: CIProvider): BranchChoice[] {
  return provider === 'gitlab' ? ['protected', 'default', 'all'] : ['all', 'default']
}

/** Where a pipeline's top-level configuration file is. */
export type DefinitionCase = 'own' | 'custom' | 'central'

/** The default file of a pipeline definition case. */
export function defaultDefinitionFile(provider: CIProvider, c: DefinitionCase): string {
  if (provider === 'github') return '.github/workflows/openctem.yml'
  return c === 'own' ? '.gitlab-ci.yml' : ''
}

/**
 * A pipeline definition as the token names it.
 * GitLab (ci_config_ref_uri): `host/group/project//path/to/file.yml@refs/heads/main`.
 * GitHub (job_workflow_ref): `owner/repo/.github/workflows/file.yml@refs/heads/main`.
 * `branch` may be a pattern (`*`) or a full ref (`refs/tags/v*`).
 */
export function pipelineDefinition(
  provider: CIProvider,
  { host, project, file, branch }: { host: string; project: string; file: string; branch: string }
): string {
  const p = project.trim().replace(/^\/+|\/+$/g, '')
  const f = file.trim().replace(/^\/+/, '')
  const b = branch.trim() || 'main'
  if (!p || !f) return ''
  const ref = b.startsWith('refs/') ? b : `refs/heads/${b}`
  if (provider === 'gitlab') {
    const h = host.trim() || 'gitlab.com'
    return `${h}/${p}//${f}@${ref}`
  }
  return `${p}/${f}@${ref}`
}

/** Whether a pipeline definition entry has the shape the server accepts (`<path>@<ref>`). */
export function isPipelineDefinition(provider: CIProvider, value: string): boolean {
  const at = value.lastIndexOf('@')
  if (at <= 0 || at === value.length - 1) return false
  const path = value.slice(0, at)
  return provider === 'gitlab' ? path.includes('//') : path.split('/').length >= 3
}

/** Why a sample token's signature could not be checked, as a cause class. */
export type VerifyCause =
  | { kind: 'private_address' }
  | { kind: 'unreachable' }
  | { kind: 'issuer_mismatch'; token: string; configured: string }
  | { kind: 'audience' }
  | { kind: 'expired' }
  | { kind: 'signature' }
  | { kind: 'other' }

/**
 * The cause class of a verification error the API returns as text (the
 * preview's verify_error). Known texts of the server's token check map to a
 * class; anything else is "other" and the text is shown as it is.
 */
export function verifyCause(message: string, configuredIssuer = ''): VerifyCause {
  const m = message.toLowerCase()
  if (m.includes('blocked address') || m.includes('private')) return { kind: 'private_address' }
  const mismatch = message.match(/issuer "([^"]+)" does not match "([^"]+)"/)
  if (mismatch) return { kind: 'issuer_mismatch', token: mismatch[1], configured: mismatch[2] }
  const tokIss = message.match(/\biss(?:uer)?\b[^"]*"([^"]+)"/)
  if (m.includes('issuer') && tokIss && configuredIssuer && tokIss[1] !== configuredIssuer)
    return { kind: 'issuer_mismatch', token: tokIss[1], configured: configuredIssuer }
  if (m.includes('jwks unavailable') || m.includes('discovery') || m.includes('timeout'))
    return { kind: 'unreachable' }
  if (m.includes('aud')) return { kind: 'audience' }
  if (m.includes('expired') || m.includes('exp ')) return { kind: 'expired' }
  if (m.includes('signature') || m.includes('kid') || m.includes('key'))
    return { kind: 'signature' }
  return { kind: 'other' }
}

/** A fix a refused pipeline offers, applied by editing one configuration. */
export type RefusalFix =
  | { kind: 'allowBranch'; value: string }
  | { kind: 'allowRepository'; value: string }
  | { kind: 'addDefinition'; value: string }
  | { kind: 'openDefinitions' }
  | { kind: 'protectedBranch' }

/** The pipeline definition a refusal's message names (the token's exact value), '' when absent. */
export function refusedDefinition(message = ''): string {
  return message.match(/pipeline definition "([^"]+)" is not listed/)?.[1] ?? ''
}

/** The branch name of a ref (`refs/heads/x` -> `x`); tags and others stay full. */
export function branchOf(ref = ''): string {
  return ref.startsWith('refs/heads/') ? ref.slice('refs/heads/'.length) : ref
}

/** The fixes a refusal offers, at most one per reason, in reason order. */
export function refusalFixes(r: CITokenRefusal): RefusalFix[] {
  const out: RefusalFix[] = []
  for (const code of r.reasons ?? []) {
    if (code === 'ref_not_allowed' && r.ref)
      out.push({ kind: 'allowBranch', value: branchOf(r.ref) })
    else if ((code === 'repository_not_allowed' || code === 'owner_not_allowed') && r.repository)
      out.push({ kind: 'allowRepository', value: r.repository })
    else if (code === 'workflow_not_allowed') {
      const def = refusedDefinition(r.message)
      out.push(def ? { kind: 'addDefinition', value: def } : { kind: 'openDefinitions' })
    } else if (code === 'ref_not_protected') out.push({ kind: 'protectedBranch' })
  }
  return out
}

function repoMatch(pattern: string, repo: string): boolean {
  if (pattern.endsWith('/**')) return repo.startsWith(pattern.slice(0, -2))
  const ps = pattern.split('/')
  const rs = repo.split('/')
  if (ps.length !== rs.length) return false
  return ps.every((p, i) => {
    const re = new RegExp(
      `^${p
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '[^/]*')
        .replace(/\?/g, '[^/]')}$`
    )
    return re.test(rs[i])
  })
}

/**
 * Whether a configuration names a repository (by owner or repository rule),
 * so a refusal of that repository belongs to it. Case-insensitive, as the
 * server matches owners and repositories.
 */
export function configNames(c: CITrustConfig, repository: string, provider?: string): boolean {
  if (provider && c.provider !== provider) return false
  const repo = repository.toLowerCase()
  if (!repo) return false
  const owner = repo.split('/')[0]
  const r = c.rules ?? {}
  if ((r.owners ?? []).some((o) => o.toLowerCase() === owner)) return true
  return (r.repositories ?? []).some((p) => repoMatch(p.toLowerCase(), repo))
}

/** The refusals that belong to a configuration (it names the repository). */
export function refusalsOf(c: CITrustConfig, list: CITokenRefusal[]): CITokenRefusal[] {
  return list.filter((r) => configNames(c, r.repository ?? '', r.provider))
}
