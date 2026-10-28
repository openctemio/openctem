'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'

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

export interface AdminMcpClientList {
  data: AdminMcpClient[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

const KEY = '/mcp-clients'

/**
 * One page of MCP clients with usage counts (any administrator; no tenant
 * data), newest first. q matches part of the client_id (its host) or the
 * declared name; blocked narrows to blocked or unblocked clients.
 */
export function useMcpClients(q: string, blocked: boolean | null, page = 1, perPage = 25) {
  const params = new URLSearchParams({ page: String(page), per_page: String(perPage) })
  if (q.trim()) params.set('q', q.trim())
  if (blocked !== null) params.set('blocked', String(blocked))
  return useSWR<AdminMcpClientList>(`${KEY}?${params}`, adminFetcher, { keepPreviousData: true })
}

/** Blocks or unblocks a client everywhere (ops_admin or super_admin). */
export function setMcpClientBlocked(id: string, blocked: boolean) {
  return adminFetch<void>(`${KEY}/${encodeURIComponent(id)}/${blocked ? 'block' : 'unblock'}`, {
    method: 'POST',
  })
}
