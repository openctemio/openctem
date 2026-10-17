'use client'

/**
 * The organization's content catalog (api/docs/rfcs/RFC-099-content-packages.md,
 * api/docs/architecture/content-catalog.md). Reading needs content:read; every
 * change content:install, the approval option settings:write. Installs,
 * updates, rollbacks, uninstalls, decisions and the approval option need a
 * recent sign-in: the shared API client opens the step-up dialog and retries.
 */

import useSWR from 'swr'
import { del, get, post, put } from '@/lib/api/client'
import type {
  ContentCatalogSettings,
  ContentInstall,
  ContentInstallRequest,
  ContentOutcome,
  ContentPackageDetail,
  ContentPackageList,
  ContentTrust,
} from '@/lib/api/generated'
import { packagePath } from './lib'

export const CONTENT_API = '/api/v1/content'

export interface PackageQuery {
  type?: string
  q?: string
  installed?: '' | 'true' | 'false'
  page: number
  perPage: number
}

export function packagesKey(q: PackageQuery): string {
  const p = new URLSearchParams({ page: String(q.page), per_page: String(q.perPage) })
  if (q.type) p.set('type', q.type)
  if (q.q?.trim()) p.set('q', q.q.trim().slice(0, 100))
  if (q.installed) p.set('installed', q.installed)
  return `${CONTENT_API}/packages?${p}`
}

export function useContentPackages(q: PackageQuery, enabled = true) {
  return useSWR<ContentPackageList>(enabled ? packagesKey(q) : null, get, {
    keepPreviousData: true,
  })
}

export function useContentPackage(id: string | null) {
  return useSWR<ContentPackageDetail>(id ? `${CONTENT_API}/packages/${packagePath(id)}` : null, get)
}

export function useContentInstalls(enabled = true) {
  return useSWR<ContentInstall[]>(enabled ? `${CONTENT_API}/installs` : null, get)
}

export function useContentRequests(enabled = true) {
  return useSWR<ContentInstallRequest[]>(enabled ? `${CONTENT_API}/requests` : null, get)
}

export function useContentSettings(enabled = true) {
  return useSWR<ContentCatalogSettings>(enabled ? `${CONTENT_API}/settings` : null, get)
}

export function useContentTrust(enabled = true) {
  return useSWR<ContentTrust>(enabled ? `${CONTENT_API}/trust` : null, get)
}

export function installPackage(body: {
  package_id: string
  version: string
  pinned: boolean
  acknowledge_license: boolean
  note: string
}) {
  return post<ContentOutcome>(`${CONTENT_API}/installs`, body)
}

export function updatePackage(
  id: string,
  body: { version: string; acknowledge_license: boolean; note: string }
) {
  return post<ContentOutcome>(`${CONTENT_API}/installs/${packagePath(id)}/update`, body)
}

export function rollbackPackage(
  id: string,
  body: { version?: string; acknowledge_license: boolean; note: string }
) {
  return post<ContentOutcome>(`${CONTENT_API}/installs/${packagePath(id)}/rollback`, body)
}

export function pinPackage(id: string, pinned: boolean) {
  return put<ContentInstall>(`${CONTENT_API}/installs/${packagePath(id)}/pin`, { pinned })
}

/** 204 (removed, resolves undefined) or 202 with the request. */
export function uninstallPackage(id: string) {
  return del<ContentOutcome | undefined>(`${CONTENT_API}/installs/${packagePath(id)}`)
}

export function decideRequest(id: string, decision: 'approve' | 'reject', reason: string) {
  return post<ContentInstallRequest>(
    `${CONTENT_API}/requests/${encodeURIComponent(id)}/${decision}`,
    { reason }
  )
}

export function cancelRequest(id: string) {
  return post<ContentInstallRequest>(`${CONTENT_API}/requests/${encodeURIComponent(id)}/cancel`)
}

export function putContentSettings(requireApproval: boolean) {
  return put<ContentCatalogSettings>(`${CONTENT_API}/settings`, {
    require_approval: requireApproval,
  })
}
