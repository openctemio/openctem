'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'

/*
 * Scanning > Content catalog (RFC-099): the instance catalog every
 * organization installs from. Any administrator reads it; importing a signed
 * bundle, publishing an instance package and revoking a version need a super
 * admin, a reason and the console step-up (adminFetch asks for it). The trust
 * roots are set on the server and only shown here.
 */

const BASE = '/content-catalog'

/** One package version as the console shows it (fields the API always sends). */
export interface CatalogVersion {
  id: string
  package_id: string
  version: string
  type: string
  origin: string
  title: string
  revoked: boolean
  revoke_reason?: string
  signatures: string[]
}

export interface CatalogListItem {
  latest: CatalogVersion
  versions: number
}

export interface CatalogList {
  data: CatalogListItem[]
  total: number
}

export interface CatalogVersions {
  package_id: string
  versions: CatalogVersion[]
}

/** The applied signed state of the instance catalog. */
export interface CatalogTrust {
  roots_configured: number
  keyset_version: number
  index_sequence: number
  index_expires_at?: string
  index_expired: boolean
  revocations_sequence: number
  revocations_expires_at?: string
  revocations_stale: boolean
  imported_at?: string
}

/** What an import did (the API's ContentImportResponse). */
export interface ContentImportResult {
  keyset_version: number
  index_sequence: number
  unchanged: boolean
  added: number
  existing: number
  refused: { package_id: string; version: string; reason: string }[]
  revoked_versions: number
  revoked_installs: number
  auto_updated: number
  revocations_stale: boolean
}

export function useCatalogTrust() {
  return useSWR<CatalogTrust>(BASE, adminFetcher)
}

export function useCatalogPackages(q: string, type: string, page: number, perPage: number) {
  const p = new URLSearchParams({ page: String(page), per_page: String(perPage) })
  if (q.trim()) p.set('q', q.trim())
  if (type) p.set('type', type)
  return useSWR<CatalogList>(`${BASE}/packages?${p}`, adminFetcher, {
    keepPreviousData: true,
  })
}

export function useCatalogVersions(packageId: string | null) {
  return useSWR<CatalogVersions>(
    packageId
      ? `${BASE}/packages/${packageId.split('/').map(encodeURIComponent).join('/')}/versions`
      : null,
    adminFetcher
  )
}

/** Imports a signed bundle (tar or tar.gz). The reason goes first: the API streams the bundle last. */
export function importCatalogBundle(bundle: File, reason: string) {
  const form = new FormData()
  form.set('reason', reason)
  form.set('bundle', bundle)
  return adminFetch<ContentImportResult>(`${BASE}/import`, { method: 'POST', body: form })
}

/** Publishes an instance package from its package.yaml and artifact. */
export function publishInstancePackage(input: {
  manifest: File
  artifact: File
  acknowledgeSecrets: boolean
  reason: string
}) {
  const form = new FormData()
  form.set('reason', input.reason)
  form.set('acknowledge_secrets', input.acknowledgeSecrets ? 'true' : 'false')
  form.set('manifest', input.manifest)
  form.set('artifact', input.artifact)
  return adminFetch<CatalogVersion>(`${BASE}/packages`, { method: 'POST', body: form })
}

/** Revokes one version: every installation of it becomes revoked. */
export function revokeCatalogVersion(packageId: string, version: string, reason: string) {
  return adminFetch<CatalogVersion>(`${BASE}/packages/revoke`, {
    method: 'POST',
    body: { package_id: packageId, version, reason },
  })
}
