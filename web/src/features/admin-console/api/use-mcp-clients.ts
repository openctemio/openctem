'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from './admin-client'

/** An AI application (MCP client) as the platform console lists it. */
export interface AdminMcpClient {
  id: string
  client_id: string
  name: string
  kind: 'metadata_document' | 'organization' | 'dynamic'
  host?: string
  redirect_uris: string[]
  blocked: boolean
  created_at: string
  active_connections: number
  organizations: number
  last_used_at?: string
}

interface AdminMcpClientList {
  data: AdminMcpClient[]
}

const KEY = '/mcp-clients'

/** Every MCP client with usage counts (any administrator; no tenant data). */
export function useMcpClients() {
  return useSWR<AdminMcpClientList>(KEY, adminFetcher)
}

/** Blocks or unblocks a client everywhere (ops_admin or super_admin). */
export function setMcpClientBlocked(id: string, blocked: boolean) {
  return adminFetch<void>(`${KEY}/${encodeURIComponent(id)}/${blocked ? 'block' : 'unblock'}`, {
    method: 'POST',
  })
}
