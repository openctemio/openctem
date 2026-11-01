/**
 * Proxy pool hooks: /api/v1/proxy-pools. Pass `enabled: false` when the
 * caller lacks sensors:egress:read so no request (and no 403) is made. The
 * API is the authority on every write.
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'

import { useTenant } from '@/context/tenant-provider'
import { del, get, patch, post, put } from '@/lib/api/client'
import { API_BASE, proxyPoolEndpoints } from '@/lib/api/endpoints'

import type {
  CreateProxyPoolRequest,
  ProxyAssignment,
  ProxyAssignmentList,
  ProxyPool,
  ProxyPoolList,
  ScannerAddressList,
  SetProxyAssignmentRequest,
  UpdateProxyEndpointRequest,
  UpdateProxyPoolRequest,
} from '../types'

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  errorRetryCount: 2,
}

/**
 * How often the Proxies page re-reads health while it is visible: endpoint
 * scores move with every scan report, and a quarantine ends on its own.
 * SWR skips the refresh while the tab is hidden or offline.
 */
export const PROXY_HEALTH_REFRESH_MS = 30_000

/**
 * The organization's pools, with their health as of the last load. Pass
 * `refreshInterval` (PROXY_HEALTH_REFRESH_MS) where health is on screen.
 */
export function useProxyPools(enabled = true, refreshInterval = 0) {
  const { currentTenant } = useTenant()
  return useSWR<ProxyPoolList>(
    currentTenant && enabled ? proxyPoolEndpoints.list() : null,
    (url: string) => get<ProxyPoolList>(url),
    { ...defaultConfig, refreshInterval }
  )
}

/** Which pool each sensor uses (a sensor without a row inherits). */
export function useProxyAssignments(enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<ProxyAssignmentList>(
    currentTenant && enabled ? proxyPoolEndpoints.assignments() : null,
    (url: string) => get<ProxyAssignmentList>(url),
    defaultConfig
  )
}

/** The addresses the organization's scans leave from (sensors:egress:read). */
export function useScannerAddresses(enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<ScannerAddressList>(
    currentTenant && enabled ? proxyPoolEndpoints.scannerAddresses() : null,
    (url: string) => get<ScannerAddressList>(url),
    defaultConfig
  )
}

/** Revalidates every proxy pool request (list, assignments), keeping the data on screen. */
export async function invalidateProxyPools() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.startsWith(API_BASE.PROXY_POOLS))
}

export function createProxyPool(body: CreateProxyPoolRequest) {
  return post<ProxyPool>(proxyPoolEndpoints.create(), body)
}

export function updateProxyPool(poolId: string, body: UpdateProxyPoolRequest) {
  return patch<ProxyPool>(proxyPoolEndpoints.update(poolId), body)
}

export function deleteProxyPool(poolId: string) {
  return del<void>(proxyPoolEndpoints.delete(poolId))
}

/** Replaces the endpoint list from a paste list; the server parses, validates and encrypts. */
export function saveProxyEndpoints(poolId: string, text: string) {
  return put<ProxyPool>(proxyPoolEndpoints.endpoints(poolId), { text })
}

export function updateProxyEndpoint(
  poolId: string,
  endpointId: string,
  body: UpdateProxyEndpointRequest
) {
  return patch<unknown>(proxyPoolEndpoints.endpoint(poolId, endpointId), body)
}

export function setProxyAssignment(sensorId: string, body: SetProxyAssignmentRequest) {
  return put<ProxyAssignment>(proxyPoolEndpoints.assignment(sensorId), body)
}
