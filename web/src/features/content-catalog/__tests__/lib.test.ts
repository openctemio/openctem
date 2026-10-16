import { describe, expect, it } from 'vitest'
import type {
  ContentInstall,
  ContentInstallRequest,
  ContentPackageVersion,
  ContentTrust,
} from '@/lib/api/generated'
import {
  approvalState,
  candidateVersions,
  needsLicenseAck,
  packageActions,
  packagePath,
  permissionDiff,
  requestActions,
  sortRequests,
  splitPackageId,
  trustBanner,
} from '../lib'

const v = (version: string, extra: Partial<ContentPackageVersion> = {}): ContentPackageVersion =>
  ({ version, package_id: 'acme/web-rules', revoked: false, ...extra }) as ContentPackageVersion

const installAt = (version: string): ContentInstall =>
  ({ package_id: 'acme/web-rules', status: 'active', installed: v(version) }) as ContentInstall

describe('package ids', () => {
  it('splits and encodes a valid id', () => {
    expect(splitPackageId('acme/web-rules')).toEqual(['acme', 'web-rules'])
    expect(packagePath('acme/web-rules')).toBe('acme/web-rules')
  })

  it('refuses ids that could change the API path', () => {
    for (const bad of ['acme/../x', 'acme/x/y', '../x', 'ACME/x', 'acme%2Fx', '', 'acme/']) {
      expect(splitPackageId(bad)).toBeNull()
      expect(() => packagePath(bad)).toThrow()
    }
  })
})

describe('permissionDiff', () => {
  it('reports nothing when the new version asks for the same or less', () => {
    const d = permissionDiff(
      {
        tier: 'T1',
        side_effects: 'state-changing',
        network: 'declared-hosts',
        declared_hosts: ['a.example.com'],
      },
      { tier: 'T0', side_effects: 'none', network: 'targets-only', declared_hosts: [] }
    )
    expect(d.widens).toBe(false)
    expect(d).toMatchObject({ tier: false, sideEffects: false, network: false, newHosts: [] })
  })

  it('flags a higher tier, wider network, more side effects and new hosts, credentials and scopes', () => {
    const d = permissionDiff(
      {
        tier: 'T0',
        side_effects: 'none',
        network: 'targets-only',
        declared_hosts: ['a.example.com'],
        credentials: ['git'],
        data_scopes: ['assets:read'],
      },
      {
        tier: 'T2',
        side_effects: 'destructive',
        network: 'declared-hosts',
        declared_hosts: ['a.example.com', 'b.example.com'],
        credentials: ['git', 'cloud'],
        data_scopes: ['assets:read', 'findings:read'],
      }
    )
    expect(d).toEqual({
      widens: true,
      tier: true,
      sideEffects: true,
      network: true,
      newHosts: ['b.example.com'],
      newCredentials: ['cloud'],
      newDataScopes: ['findings:read'],
    })
  })

  it('treats a single new host as widening', () => {
    const d = permissionDiff({ declared_hosts: [] }, { declared_hosts: ['c.example.com'] })
    expect(d.widens).toBe(true)
    expect(d.tier).toBe(false)
  })
})

describe('trustBanner', () => {
  const base: ContentTrust = {
    roots_configured: 1,
    imported_at: '2026-10-01T00:00:00Z',
    index_expired: false,
    revocations_stale: false,
  } as ContentTrust

  it('shows nothing while loading or when the catalog is current', () => {
    expect(trustBanner(undefined)).toBeNull()
    expect(trustBanner(base)).toBeNull()
  })

  it('informs when no trust root is configured, before anything else', () => {
    expect(trustBanner({ ...base, roots_configured: 0, index_expired: true })).toEqual({
      tone: 'info',
      reason: 'no-roots',
    })
  })

  it('informs when nothing has been imported', () => {
    expect(trustBanner({ ...base, imported_at: undefined })).toEqual({
      tone: 'info',
      reason: 'no-import',
    })
  })

  it('warns on an expired index and a stale revocation list', () => {
    expect(trustBanner({ ...base, index_expired: true })).toEqual({
      tone: 'warning',
      reasons: ['index-expired'],
    })
    expect(trustBanner({ ...base, index_expired: true, revocations_stale: true })).toEqual({
      tone: 'warning',
      reasons: ['index-expired', 'revocations-stale'],
    })
  })
})

describe('candidateVersions', () => {
  const versions = [
    v('2.0.0'),
    v('1.2.0', { revoked: true }),
    v('1.1.0'),
    v('1.0.0'),
    v('2.0.0-rc.1'),
  ]

  it('lists newer and older versions, never revoked ones', () => {
    expect(candidateVersions(versions, '1.1.0', 'newer').map((x) => x.version)).toEqual([
      '2.0.0',
      '2.0.0-rc.1',
    ])
    expect(candidateVersions(versions, '1.1.0', 'older').map((x) => x.version)).toEqual(['1.0.0'])
  })

  it('orders a pre-release before its release', () => {
    expect(candidateVersions(versions, '2.0.0-rc.1', 'newer').map((x) => x.version)).toEqual([
      '2.0.0',
    ])
  })

  it('compares pre-release numbers numerically', () => {
    const rcs = [v('1.0.0-rc.10'), v('1.0.0-rc.9'), v('1.0.0-rc.2')]
    expect(candidateVersions(rcs, '1.0.0-rc.9', 'newer').map((x) => x.version)).toEqual([
      '1.0.0-rc.10',
    ])
  })

  it('is empty without an installed version', () => {
    expect(candidateVersions(versions, undefined, 'newer')).toEqual([])
  })
})

describe('packageActions', () => {
  const versions = [v('2.0.0'), v('1.0.0'), v('0.9.0')]

  it('offers nothing without content:install', () => {
    expect(packageActions({ canInstall: false, versions, install: installAt('1.0.0') })).toEqual({
      install: false,
      update: false,
      rollback: false,
      pin: false,
      uninstall: false,
    })
    expect(packageActions({ canInstall: false, versions }).install).toBe(false)
  })

  it('offers install only when not installed and some version is not revoked', () => {
    expect(packageActions({ canInstall: true, versions })).toMatchObject({
      install: true,
      update: false,
      uninstall: false,
    })
    expect(
      packageActions({ canInstall: true, versions: [v('1.0.0', { revoked: true })] }).install
    ).toBe(false)
  })

  it('offers update, rollback, pin and uninstall on an installation', () => {
    expect(packageActions({ canInstall: true, versions, install: installAt('1.0.0') })).toEqual({
      install: false,
      update: true,
      rollback: true,
      pin: true,
      uninstall: true,
    })
    expect(
      packageActions({ canInstall: true, versions, install: installAt('2.0.0') })
    ).toMatchObject({ update: false, rollback: true })
  })

  it('offers nothing while a request for the package is pending', () => {
    const pending = { id: 'r1', status: 'pending' } as ContentInstallRequest
    const a = packageActions({ canInstall: true, versions, install: installAt('1.0.0'), pending })
    expect(Object.values(a).some(Boolean)).toBe(false)
  })
})

describe('requestActions', () => {
  const req = (over: Partial<ContentInstallRequest> = {}) =>
    ({ id: 'r1', status: 'pending', requested_by: 'u-alice', ...over }) as ContentInstallRequest

  it('lets another member decide and the requester cancel', () => {
    expect(requestActions(req(), 'u-bob', true)).toEqual({ decide: true, cancel: false })
    expect(requestActions(req(), 'u-alice', true)).toEqual({ decide: false, cancel: true })
  })

  it('offers nothing without content:install or once decided', () => {
    expect(requestActions(req(), 'u-bob', false)).toEqual({ decide: false, cancel: false })
    expect(requestActions(req({ status: 'approved' }), 'u-bob', true)).toEqual({
      decide: false,
      cancel: false,
    })
  })

  it('does not treat an unknown user as the requester', () => {
    expect(requestActions(req({ requested_by: undefined }), undefined, true)).toEqual({
      decide: true,
      cancel: false,
    })
  })
})

describe('sortRequests', () => {
  it('puts pending first, newest first within each group', () => {
    const rows = [
      { id: 'a', status: 'approved', created_at: '2026-10-03T00:00:00Z' },
      { id: 'b', status: 'pending', created_at: '2026-10-01T00:00:00Z' },
      { id: 'c', status: 'pending', created_at: '2026-10-02T00:00:00Z' },
      { id: 'd', status: 'rejected', created_at: '2026-10-04T00:00:00Z' },
    ] as ContentInstallRequest[]
    expect(sortRequests(rows).map((r) => r.id)).toEqual(['c', 'b', 'd', 'a'])
  })
})

describe('needsLicenseAck', () => {
  it('asks only when the license forbids use as a service', () => {
    expect(needsLicenseAck(v('1.0.0', { license: { spdx: 'X', service_use: false } }))).toBe(true)
    expect(needsLicenseAck(v('1.0.0', { license: { spdx: 'MIT', service_use: true } }))).toBe(false)
    expect(needsLicenseAck(undefined)).toBe(false)
  })
})

describe('approvalState', () => {
  it('is off, on, or switching off with the time it ends', () => {
    expect(approvalState(undefined)).toEqual({ mode: 'off' })
    expect(approvalState({ require_approval: false })).toEqual({ mode: 'off' })
    expect(approvalState({ require_approval: true })).toEqual({ mode: 'on' })
    expect(
      approvalState({ require_approval: true, approval_off_at: '2026-10-17T10:00:00Z' })
    ).toEqual({ mode: 'switching-off', offAt: '2026-10-17T10:00:00Z' })
  })
})
