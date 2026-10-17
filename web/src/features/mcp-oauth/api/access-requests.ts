/**
 * Members' requests to approve an AI application's publisher
 * (docs/architecture/mcp-authorization.md, "Access requests").
 * Approving and allowing need a recent sign-in: the shared client asks for it.
 */

'use client'

import useSWR, { mutate as globalMutate } from 'swr'
import { get, post } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'

import { MCP_POLICY_URL } from './connections'

export interface McpAccessRequest {
  id: string
  client_host: string
  client_name: string
  client_id: string
  scopes: string[]
  requester_name: string
  request_count: number
  created_at: string
  updated_at: string
}

export const ACCESS_REQUESTS_URL = '/api/v1/mcp-access/requests'

/** The organization's waiting requests (settings:read). */
export function useAccessRequests(enabled: boolean) {
  const { currentTenant } = useTenant()
  return useSWR<{ data: McpAccessRequest[] }>(
    currentTenant && enabled ? ACCESS_REQUESTS_URL : null,
    (url: string) => get<{ data: McpAccessRequest[] }>(url)
  )
}

const refresh = () => Promise.all([globalMutate(ACCESS_REQUESTS_URL), globalMutate(MCP_POLICY_URL)])

/** Approves the request's publisher: its host joins the approved publishers. */
export async function approveAccessRequest(id: string): Promise<void> {
  await post<void>(`${ACCESS_REQUESTS_URL}/${encodeURIComponent(id)}/approve`)
  await refresh()
}

/** Declines the request; the policy does not change. */
export async function denyAccessRequest(id: string): Promise<void> {
  await post<void>(`${ACCESS_REQUESTS_URL}/${encodeURIComponent(id)}/deny`)
  await refresh()
}

const consentBase = (id: string) => `/api/v1/oauth/requests/${encodeURIComponent(id)}`

/** From a blocked consent: asks administrators to approve the publisher. */
export async function requestPublisherAccess(consentRequestId: string): Promise<void> {
  await post<void>(`${consentBase(consentRequestId)}/access-request`)
}

/** From a blocked consent, for a caller who may change the policy. */
export async function allowPublisher(consentRequestId: string): Promise<void> {
  await post<void>(`${consentBase(consentRequestId)}/allow-publisher`)
  await refresh()
}
