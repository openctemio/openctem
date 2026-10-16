/**
 * Pure rules of the Content catalog page (api/docs/rfcs/RFC-099-content-packages.md).
 * The API decides every action; these only shape what the page offers and
 * highlights, so a hidden button never stands in for a server check.
 */

import type {
  ContentCatalogSettings,
  ContentInstall,
  ContentInstallRequest,
  ContentPackagePermissions,
  ContentPackageVersion,
  ContentTrust,
} from '@/lib/api/generated'

export const CONTENT_TYPES = [
  'rules',
  'templates',
  'wordlists',
  'profiles',
  'report-templates',
  'playbooks',
  'policy-packs',
  'tool-adapters',
  'sensors',
  'feeds',
] as const

export type ContentType = (typeof CONTENT_TYPES)[number]

const TIERS = ['T0', 'T1', 'T2']
const SIDE_EFFECTS = ['none', 'state-changing', 'destructive']
const NETWORK = ['none', 'targets-only', 'declared-hosts']

/** "acme/web-rules" -> ["acme", "web-rules"]; null for anything else. */
export function splitPackageId(id: string | undefined): [string, string] | null {
  const m = /^([a-z0-9-]+)\/([a-z0-9-]+)$/.exec(id ?? '')
  return m ? [m[1], m[2]] : null
}

/** The API path of one package's installation (or detail), URL-encoded. */
export function packagePath(id: string): string {
  const parts = splitPackageId(id)
  if (!parts) throw new Error('invalid package id')
  return `${encodeURIComponent(parts[0])}/${encodeURIComponent(parts[1])}`
}

export interface PermissionDiff {
  /** Any field asks for more than the installed version. */
  widens: boolean
  tier: boolean
  sideEffects: boolean
  network: boolean
  newHosts: string[]
  newCredentials: string[]
  newDataScopes: string[]
}

function rankUp(order: string[], from?: string, to?: string): boolean {
  return order.indexOf(to ?? '') > order.indexOf(from ?? '')
}

function added(from?: string[] | null, to?: string[] | null): string[] {
  const have = new Set(from ?? [])
  return (to ?? []).filter((x) => !have.has(x))
}

/**
 * What `to` asks for beyond `from`: the same comparison the server uses to
 * decide whether an automatic update may move an installation.
 */
export function permissionDiff(
  from: ContentPackagePermissions | undefined,
  to: ContentPackagePermissions | undefined
): PermissionDiff {
  const tier = rankUp(TIERS, from?.tier, to?.tier)
  const sideEffects = rankUp(SIDE_EFFECTS, from?.side_effects, to?.side_effects)
  const network = rankUp(NETWORK, from?.network, to?.network)
  const newHosts = added(from?.declared_hosts, to?.declared_hosts)
  const newCredentials = added(from?.credentials, to?.credentials)
  const newDataScopes = added(from?.data_scopes, to?.data_scopes)
  return {
    widens:
      tier ||
      sideEffects ||
      network ||
      newHosts.length > 0 ||
      newCredentials.length > 0 ||
      newDataScopes.length > 0,
    tier,
    sideEffects,
    network,
    newHosts,
    newCredentials,
    newDataScopes,
  }
}

export type TrustBanner =
  | { tone: 'info'; reason: 'no-roots' | 'no-import' }
  | { tone: 'warning'; reasons: ('index-expired' | 'revocations-stale')[] }
  | null

/** The status line above the catalog: nothing when the catalog is current. */
export function trustBanner(trust: ContentTrust | undefined): TrustBanner {
  if (!trust) return null
  if (!trust.roots_configured) return { tone: 'info', reason: 'no-roots' }
  if (!trust.imported_at) return { tone: 'info', reason: 'no-import' }
  const reasons: ('index-expired' | 'revocations-stale')[] = []
  if (trust.index_expired) reasons.push('index-expired')
  if (trust.revocations_stale) reasons.push('revocations-stale')
  return reasons.length ? { tone: 'warning', reasons } : null
}

/** A license that does not allow running it as a service needs an acknowledgement. */
export function needsLicenseAck(v: ContentPackageVersion | undefined): boolean {
  return !!v && v.license?.service_use === false
}

function compareSemver(a: string, b: string): number {
  const parse = (s: string) => {
    const plain = s.replace(/^v/, '').split('+')[0]
    const dash = plain.indexOf('-')
    const core = dash < 0 ? plain : plain.slice(0, dash)
    const pre = dash < 0 ? '' : plain.slice(dash + 1)
    return { nums: core.split('.').map((n) => Number.parseInt(n, 10) || 0), pre }
  }
  const x = parse(a)
  const y = parse(b)
  for (let i = 0; i < 3; i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0)
    if (d !== 0) return d
  }
  if (x.pre === y.pre) return 0
  if (!x.pre) return 1
  if (!y.pre) return -1
  // Pre-release identifiers compare dot by dot: numbers numerically and below words.
  const xa = x.pre.split('.')
  const ya = y.pre.split('.')
  for (let i = 0; i < Math.max(xa.length, ya.length); i++) {
    if (xa[i] === undefined) return -1
    if (ya[i] === undefined) return 1
    const xn = /^\d+$/.test(xa[i])
    const yn = /^\d+$/.test(ya[i])
    if (xn && yn) {
      const d = Number(xa[i]) - Number(ya[i])
      if (d !== 0) return d
    } else if (xn !== yn) {
      return xn ? -1 : 1
    } else if (xa[i] !== ya[i]) {
      return xa[i] < ya[i] ? -1 : 1
    }
  }
  return 0
}

/** Versions newer (update) or older (rollback) than the installed one, not revoked. */
export function candidateVersions(
  versions: ContentPackageVersion[],
  installed: string | undefined,
  direction: 'newer' | 'older'
): ContentPackageVersion[] {
  if (!installed) return []
  return versions.filter((v) => {
    if (v.revoked || !v.version) return false
    const c = compareSemver(v.version, installed)
    return direction === 'newer' ? c > 0 : c < 0
  })
}

export interface PackageActions {
  install: boolean
  update: boolean
  rollback: boolean
  pin: boolean
  uninstall: boolean
}

/**
 * Which actions the package sheet offers. Writes need content:install; a
 * pending request blocks another change of the same package (the API allows
 * one at a time).
 */
export function packageActions(input: {
  canInstall: boolean
  versions: ContentPackageVersion[]
  install?: ContentInstall | null
  pending?: ContentInstallRequest | null
}): PackageActions {
  const none: PackageActions = {
    install: false,
    update: false,
    rollback: false,
    pin: false,
    uninstall: false,
  }
  if (!input.canInstall || input.pending) return none
  const installed = input.install?.installed?.version
  if (!input.install || !installed) {
    return { ...none, install: input.versions.some((v) => !v.revoked) }
  }
  return {
    install: false,
    update: candidateVersions(input.versions, installed, 'newer').length > 0,
    rollback: candidateVersions(input.versions, installed, 'older').length > 0,
    pin: true,
    uninstall: true,
  }
}

export interface RequestActions {
  decide: boolean
  cancel: boolean
}

/** Approve/reject belong to another member; cancel to the requester. */
export function requestActions(
  req: ContentInstallRequest,
  userId: string | undefined,
  canInstall: boolean
): RequestActions {
  if (!canInstall || req.status !== 'pending') return { decide: false, cancel: false }
  const own = !!userId && req.requested_by === userId
  return { decide: !own, cancel: own }
}

/** Pending requests first, then newest first. */
export function sortRequests(reqs: ContentInstallRequest[]): ContentInstallRequest[] {
  return [...reqs].sort((a, b) => {
    const pa = a.status === 'pending' ? 0 : 1
    const pb = b.status === 'pending' ? 0 : 1
    if (pa !== pb) return pa - pb
    return (b.created_at ?? '').localeCompare(a.created_at ?? '')
  })
}

export type ApprovalState =
  | { mode: 'on' }
  | { mode: 'off' }
  /** Switched off, but approval stays required until `offAt` (24 hours after the change). */
  | { mode: 'switching-off'; offAt: string }

/**
 * The approval option as the page shows it. The API keeps require_approval
 * true for a day after it is switched off and reports when it ends; turning
 * it back on cancels that.
 */
export function approvalState(s: ContentCatalogSettings | undefined): ApprovalState {
  if (!s?.require_approval) return { mode: 'off' }
  if (s.approval_off_at) return { mode: 'switching-off', offAt: s.approval_off_at }
  return { mode: 'on' }
}
