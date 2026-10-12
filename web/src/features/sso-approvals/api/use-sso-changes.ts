/**
 * SSO changes awaiting an owner's approval (RFC-022).
 *
 * A platform administrator's SAML or identity-provider change to an
 * organization that has an owner is stored as pending; it takes effect only
 * when an owner approves it here. Owner only:
 * /api/v1/tenants/{tenant}/settings/sso/changes.
 */

'use client'

import useSWR from 'swr'
import { get, post } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'

export type SSOChangeStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'superseded'

export interface SSOChange {
  id: string
  kind: 'saml_config' | 'idp_create' | 'idp_update' | 'domain_jit'
  target_id?: string
  status: SSOChangeStatus
  summary: string
  payload: Record<string, unknown>
  certificate_sha256?: string
  requested_by: string
  created_at: string
  expires_at: string
  decided_at?: string
  decided_by?: string
}

/** True when an SSO write answered with a change that waits for an owner. */
export function isPendingSSOChange(res: unknown): res is SSOChange {
  return (
    typeof res === 'object' &&
    res !== null &&
    (res as { status?: unknown }).status === 'pending' &&
    typeof (res as { kind?: unknown }).kind === 'string'
  )
}

/** Shown to the platform administrator when a change waits for an owner. */
export const PENDING_SSO_MESSAGE =
  'Submitted for approval: an owner of the organization must approve this change before it takes effect.'

const base = (tenant: string) => `/api/v1/tenants/${tenant}/settings/sso/changes`

/** The organization's SSO changes. Pass `enabled: false` for a non-owner (the API refuses them). */
export function useSSOChanges({ enabled = true, all = false } = {}) {
  const { currentTenant } = useTenant()
  const key =
    currentTenant && enabled ? `${base(currentTenant.id)}${all ? '?status=all' : ''}` : null
  return useSWR<{ changes: SSOChange[] }>(key, (url: string) => get<{ changes: SSOChange[] }>(url))
}

export function decideSSOChange(tenantId: string, id: string, decision: 'approve' | 'reject') {
  return post<SSOChange>(`${base(tenantId)}/${id}/${decision}`, {})
}
