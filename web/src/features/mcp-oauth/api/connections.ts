/**
 * Connected AI applications and the organization MCP policy (RFC-062).
 * SWR over /api/v1/mcp-access/*; the tenant comes from the session.
 */

'use client'

import useSWR, { mutate as globalMutate } from 'swr'
import { get, put, del } from '@/lib/api/client'
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
  platform_client_hosts: string[]
  available_scopes: McpScopeInfo[]
}

export type McpPolicyUpdate = Pick<
  McpPolicy,
  'enabled' | 'any_client' | 'client_hosts' | 'scopes' | 'api_keys_allowed' | 'refresh_days'
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

/** The scope list in words, for a connection row. */
export function scopeLabel(scope: string): string {
  switch (scope) {
    case 'mcp:findings.read':
      return 'Findings'
    case 'mcp:assets.read':
      return 'Assets'
    case 'mcp:compliance.read':
      return 'Compliance'
    case 'mcp:pentest.read':
      return 'Pentest'
    default:
      return scope
  }
}
