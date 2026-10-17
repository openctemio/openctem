/**
 * Connected AI applications and the organization MCP policy (RFC-062).
 * SWR over /api/v1/mcp-access/*; the tenant comes from the session.
 */

'use client'

import useSWR, { mutate as globalMutate } from 'swr'
import { get, post, put, del } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'

export interface McpConnection {
  id: string
  client_name: string
  client_id: string
  client_kind: 'metadata_document' | 'organization' | 'dynamic'
  client_host?: string
  user_id: string
  user_name?: string
  user_email?: string
  scopes: string[]
  created_at: string
  last_used_at?: string
  last_used_ip?: string
  expires_at: string
}

interface McpConnectionList {
  data: McpConnection[]
}

export interface McpScopeInfo {
  scope: string
  title: string
  write: boolean
}

export interface McpPolicy {
  enabled: boolean
  any_client: boolean
  client_hosts: string[]
  scopes: string[]
  api_keys_allowed: boolean
  refresh_days: number
  effective_refresh_days: number
  /** Only DPoP-bound tokens (proof of the client key on every request). */
  require_dpop: boolean
  /** Highest TLP of a pentest campaign sent to AI applications (default amber). */
  max_tlp: 'clear' | 'green' | 'amber' | 'amber_strict' | 'red'
  platform_client_hosts: string[]
  available_scopes: McpScopeInfo[]
}

export type McpPolicyUpdate = Pick<
  McpPolicy,
  | 'enabled'
  | 'any_client'
  | 'client_hosts'
  | 'scopes'
  | 'api_keys_allowed'
  | 'refresh_days'
  | 'require_dpop'
  | 'max_tlp'
>

export const MY_CONNECTIONS_URL = '/api/v1/mcp-access/my-connections'
export const ORG_CONNECTIONS_URL = '/api/v1/mcp-access/connections'
export const MCP_POLICY_URL = '/api/v1/mcp-access/settings'

/** The signed-in person's connections in the current organization. */
export function useMyConnections() {
  const { currentTenant } = useTenant()
  return useSWR<McpConnectionList>(currentTenant ? MY_CONNECTIONS_URL : null, (url: string) =>
    get<McpConnectionList>(url)
  )
}

/** Every connection of the organization (owners and administrators). */
export function useOrgConnections(enabled: boolean) {
  const { currentTenant } = useTenant()
  return useSWR<McpConnectionList>(
    currentTenant && enabled ? ORG_CONNECTIONS_URL : null,
    (url: string) => get<McpConnectionList>(url)
  )
}

/** Ends one of the person's own connections. */
export async function revokeMyConnection(id: string): Promise<void> {
  await del<void>(`${MY_CONNECTIONS_URL}/${encodeURIComponent(id)}`)
  await Promise.all([globalMutate(MY_CONNECTIONS_URL), globalMutate(ORG_CONNECTIONS_URL)])
}

/** Ends any connection of the organization (owners and administrators). */
export async function revokeOrgConnection(id: string): Promise<void> {
  await del<void>(`${ORG_CONNECTIONS_URL}/${encodeURIComponent(id)}`)
  await Promise.all([globalMutate(MY_CONNECTIONS_URL), globalMutate(ORG_CONNECTIONS_URL)])
}

export function useMcpPolicy(enabled: boolean) {
  const { currentTenant } = useTenant()
  return useSWR<McpPolicy>(currentTenant && enabled ? MCP_POLICY_URL : null, (url: string) =>
    get<McpPolicy>(url)
  )
}

export async function updateMcpPolicy(p: McpPolicyUpdate): Promise<McpPolicy> {
  const saved = await put<McpPolicy>(MCP_POLICY_URL, p)
  await globalMutate(MCP_POLICY_URL, saved, { revalidate: false })
  return saved
}

/** The writable fields of a policy read from the server. */
export function policyUpdate(p: McpPolicy): McpPolicyUpdate {
  return {
    enabled: p.enabled,
    any_client: p.any_client,
    client_hosts: p.client_hosts,
    scopes: p.scopes,
    api_keys_allowed: p.api_keys_allowed,
    refresh_days: p.refresh_days,
    require_dpop: p.require_dpop,
    max_tlp: p.max_tlp,
  }
}

/**
 * Changes some fields of the stored policy and keeps the rest as last read
 * (the API replaces the whole policy).
 */
export function patchMcpPolicy(
  current: McpPolicy,
  patch: Partial<McpPolicyUpdate>
): Promise<McpPolicy> {
  return updateMcpPolicy({ ...policyUpdate(current), ...patch })
}

export interface McpOrgClient {
  id: string
  client_id: string
  name: string
  redirect_uris: string[]
  created_at: string
}

export const ORG_CLIENTS_URL = '/api/v1/mcp-access/clients'

/** Applications the organization registered in advance. */
export function useOrgClients(enabled: boolean) {
  const { currentTenant } = useTenant()
  return useSWR<{ data: McpOrgClient[] }>(
    currentTenant && enabled ? ORG_CLIENTS_URL : null,
    (url: string) => get<{ data: McpOrgClient[] }>(url)
  )
}

export async function createOrgClient(name: string, redirectUris: string[]): Promise<McpOrgClient> {
  const created = await post<McpOrgClient>(ORG_CLIENTS_URL, { name, redirect_uris: redirectUris })
  await globalMutate(ORG_CLIENTS_URL)
  return created
}

export async function deleteOrgClient(id: string): Promise<void> {
  await del<void>(`${ORG_CLIENTS_URL}/${encodeURIComponent(id)}`)
  await Promise.all([
    globalMutate(ORG_CLIENTS_URL),
    globalMutate(ORG_CONNECTIONS_URL),
    globalMutate(MY_CONNECTIONS_URL),
  ])
}
