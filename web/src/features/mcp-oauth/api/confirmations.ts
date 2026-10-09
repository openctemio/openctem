/**
 * Write-action confirmations (RFC-062 §10): an AI application asked to change
 * data; nothing happens until the person approves the exact action here.
 */

import { csrfFetch } from '@/lib/api/client'

export interface McpConfirmation {
  id: string
  tool: string
  /** What will happen, described by the server. */
  summary: string
  client_name: string
  status: 'pending' | 'approved' | 'denied' | 'used'
  expired: boolean
  expires_at: string
}

const base = (id: string) => `/api/v1/mcp-access/confirmations/${encodeURIComponent(id)}`

export async function fetchConfirmation(id: string): Promise<McpConfirmation | null> {
  const r = await csrfFetch(base(id), { method: 'GET' })
  if (r.status === 404) return null
  if (!r.ok) throw new Error('Could not load the request')
  return (await r.json()) as McpConfirmation
}

export async function decideConfirmation(id: string, approve: boolean): Promise<boolean> {
  const r = await csrfFetch(`${base(id)}/${approve ? 'approve' : 'deny'}`, { method: 'POST' })
  return r.ok
}
