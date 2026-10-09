'use client'

import useSWR from 'swr'
import type {
  ContentChannelResponse,
  ContentSigningKeyResponse,
  PlatformContentPackListResponse,
  PlatformContentPackResponse,
} from '@/lib/api/generated'
import { adminFetch, adminFetcher, ADMIN_API } from './admin-client'

export const CONTENT_PACKS = '/content-packs'

export interface ContentPackQuery {
  kind?: string
  name?: string
  status?: '' | 'active' | 'revoked'
  page?: number
  perPage?: number
}

/** The platform's content packs, newest first (any admin). */
export function useContentPacks(q: ContentPackQuery) {
  const p = new URLSearchParams({ page: String(q.page ?? 1), per_page: String(q.perPage ?? 25) })
  if (q.kind) p.set('kind', q.kind)
  if (q.name?.trim()) p.set('name', q.name.trim())
  if (q.status) p.set('status', q.status)
  return useSWR<PlatformContentPackListResponse>(`${CONTENT_PACKS}?${p}`, adminFetcher, {
    keepPreviousData: true,
  })
}

export function useContentPack(id: string | null) {
  return useSWR<PlatformContentPackResponse>(
    id ? `${CONTENT_PACKS}/${encodeURIComponent(id)}` : null,
    adminFetcher
  )
}

/** Which pack each (name, channel) points at (any admin). */
export function useContentChannels() {
  return useSWR<{ data: ContentChannelResponse[] }>(`${CONTENT_PACKS}/channels`, adminFetcher)
}

/** The platform content signing key (sensors verify packs with it). */
export function useContentSigningKey() {
  return useSWR<ContentSigningKeyResponse>(`${CONTENT_PACKS}/signing-key`, adminFetcher)
}

/** Where a pack's signed archive downloads from (through the console proxy). */
export function contentPackDownloadUrl(id: string): string {
  return `${ADMIN_API}${CONTENT_PACKS}/${encodeURIComponent(id)}/download`
}

export interface UploadPackInput {
  name: string
  version: string
  kind: string
  archive: File
  acknowledgeSecrets: boolean
  /** Why (kept in the admin audit row) and a fresh authenticator code. */
  reason: string
  totpCode: string
}

/** Uploads a tar or tar.gz as a new pack (super admin; audited). */
export function uploadContentPack(input: UploadPackInput) {
  const form = new FormData()
  form.set('name', input.name)
  form.set('version', input.version)
  form.set('kind', input.kind)
  form.set('acknowledge_secrets', input.acknowledgeSecrets ? 'true' : 'false')
  form.set('reason', input.reason)
  form.set('totp_code', input.totpCode)
  form.set('archive', input.archive)
  return adminFetch<PlatformContentPackResponse>(CONTENT_PACKS, { method: 'POST', body: form })
}

export interface ImportPackInput {
  name: string
  version: string
  kind: string
  url: string
  digest: string
  acknowledge_secrets: boolean
  reason: string
  totp_code: string
}

/** Imports a release by https URL, checked against its sha256 (super admin; audited). */
export function importContentPack(input: ImportPackInput) {
  return adminFetch<PlatformContentPackResponse>(`${CONTENT_PACKS}/import`, {
    method: 'POST',
    body: input,
  })
}

/** Revokes a pack (super admin; audited). Channels pointing at it are cleared. */
export function revokeContentPack(id: string, proof: { reason: string; totp_code?: string }) {
  return adminFetch<unknown>(`${CONTENT_PACKS}/${encodeURIComponent(id)}/revoke`, {
    method: 'POST',
    body: proof,
  })
}

/** Points a channel (stable, canary) at a pack (super admin; audited). */
export function setContentChannel(
  channel: string,
  input: { pack_id: string; reason: string; totp_code?: string }
) {
  return adminFetch<ContentChannelResponse>(
    `${CONTENT_PACKS}/channels/${encodeURIComponent(channel)}`,
    { method: 'PUT', body: input }
  )
}
