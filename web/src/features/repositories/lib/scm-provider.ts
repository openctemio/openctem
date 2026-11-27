import type { SCMProvider } from '@/features/assets/types/asset.types'

/**
 * The git host a repository lives on, read from a URL or a "host/org/repo"
 * name. Returns null when it is not a host we recognise: callers show a
 * neutral "Git" label then, never a guessed provider.
 */
export function scmProviderFromHost(value: string | null | undefined): SCMProvider | null {
  if (!value) return null
  let host = value.trim().toLowerCase()
  const scheme = host.indexOf('://')
  if (scheme >= 0) host = host.slice(scheme + 3)
  // "git@host:org/repo" (ssh) and "user@host/..." forms.
  const at = host.indexOf('@')
  const sep = host.search(/[/:]/)
  if (at >= 0 && (sep < 0 || at < sep)) host = host.slice(at + 1)
  host = host.split(/[/:?#]/)[0]
  if (!host) return null
  if (host === 'github.com' || host.startsWith('github.')) return 'github'
  if (host === 'gitlab.com' || host.startsWith('gitlab.')) return 'gitlab'
  if (host === 'bitbucket.org' || host.startsWith('bitbucket.')) return 'bitbucket'
  if (host === 'dev.azure.com' || host.endsWith('.visualstudio.com')) return 'azure_devops'
  return null
}

const KNOWN: ReadonlySet<string> = new Set([
  'github',
  'gitlab',
  'bitbucket',
  'azure_devops',
  'codecommit',
  'local',
])

/**
 * The provider of a repository: the stored one when the record has it,
 * else the one its host names, else null (unknown).
 */
export function resolveScmProvider(input: {
  scmProvider?: string | null
  hosts?: Array<string | null | undefined>
}): SCMProvider | null {
  const stored = input.scmProvider?.trim().toLowerCase()
  if (stored && KNOWN.has(stored)) return stored as SCMProvider
  for (const h of input.hosts ?? []) {
    const p = scmProviderFromHost(h)
    if (p) return p
  }
  return null
}
