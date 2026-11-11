'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'
import type { SettingChange } from '../types'

/**
 * Blocked target names (RFC-154): the government and military rule of the
 * scope guardrails, the operator's own blocked names and the organizations'
 * exceptions. Any administrator reads them; a platform owner changes them
 * with a reason and a fresh authenticator code.
 */
export interface ScopeBlockedNames extends SettingChange {
  government_rule: boolean
  names: string[]
  /** SCOPE_DENY_EXTRA: always blocked, read-only here. */
  env_names: string[]
  max_exception_days: number
  /** A hosted service: a second owner approves grants, extensions and turning the rule off. */
  second_approval: boolean
  version: number
}

export type ScopeNameExceptionState = 'active' | 'expired' | 'revoked'

export interface ScopeNameException {
  id: string
  organization_id: string
  organization_name: string
  name: string
  include_subdomains: boolean
  reason: string
  authorization_ref: string
  granted_by: string
  granted_at: string
  expires_at: string
  state: ScopeNameExceptionState
  revoked_at?: string
  revoked_by?: string
  revoke_reason?: string
}

const KEY = '/settings/scope-blocked-names'
const EXCEPTIONS_KEY = `${KEY}/exceptions`

export function useScopeBlockedNames() {
  return useSWR<ScopeBlockedNames>(KEY, adminFetcher)
}

export function useScopeNameExceptions() {
  return useSWR<{ items: ScopeNameException[] }>(EXCEPTIONS_KEY, adminFetcher)
}

export function saveScopeBlockedNames(
  input: {
    government_rule: boolean
    names: string[]
    max_exception_days: number
    version: number
    reason: string
  },
  code: string
) {
  return adminFetch<ScopeBlockedNames>(KEY, {
    method: 'PUT',
    body: input,
    stepUpCode: code || undefined,
  })
}

export function grantScopeNameException(
  input: {
    organization_id: string
    name: string
    include_subdomains: boolean
    reason: string
    authorization_ref: string
    /** YYYY-MM-DD: the end of that day, UTC. */
    expires_at: string
  },
  code: string
) {
  return adminFetch<ScopeNameException>(EXCEPTIONS_KEY, {
    method: 'POST',
    body: input,
    stepUpCode: code || undefined,
  })
}

export function extendScopeNameException(
  id: string,
  input: { expires_at: string; reason: string },
  code: string
) {
  return adminFetch<ScopeNameException>(`${EXCEPTIONS_KEY}/${encodeURIComponent(id)}/extend`, {
    method: 'POST',
    body: input,
    stepUpCode: code || undefined,
  })
}

export function revokeScopeNameException(id: string, input: { reason: string }, code: string) {
  return adminFetch<ScopeNameException>(`${EXCEPTIONS_KEY}/${encodeURIComponent(id)}/revoke`, {
    method: 'POST',
    body: input,
    stepUpCode: code || undefined,
  })
}
