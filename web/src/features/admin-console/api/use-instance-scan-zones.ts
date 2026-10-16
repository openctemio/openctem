'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from './admin-client'

/**
 * Instance scan zones (RFC-100 §6.1): private ranges shared sensors may scan
 * for the organizations each zone is assigned to. Any administrator reads;
 * a super admin changes them with a reason and an authenticator code.
 */
export interface InstanceScanZone {
  id: string
  name: string
  description: string
  ranges: string[]
  sensor_ids: string[]
  organization_ids: string[]
}

interface ZoneList {
  items: InstanceScanZone[]
}

const KEY = '/instance-scan-zones'

export function useInstanceScanZones() {
  return useSWR<ZoneList>(KEY, adminFetcher)
}

interface Confirmation {
  reason: string
  totp_code: string
}

export function createInstanceScanZone(
  input: { name: string; description: string; ranges: string[] } & Confirmation
) {
  return adminFetch<InstanceScanZone>(KEY, { method: 'POST', body: input })
}

export function updateInstanceScanZone(
  id: string,
  input: { name: string; description: string; ranges: string[] } & Confirmation
) {
  return adminFetch<InstanceScanZone>(`${KEY}/${id}`, { method: 'PUT', body: input })
}

export function deleteInstanceScanZone(id: string, input: Confirmation) {
  return adminFetch<void>(`${KEY}/${id}`, { method: 'DELETE', body: input })
}

export function setInstanceScanZoneSensors(id: string, input: { ids: string[] } & Confirmation) {
  return adminFetch<InstanceScanZone>(`${KEY}/${id}/sensors`, { method: 'PUT', body: input })
}

export function setInstanceScanZoneOrganizations(
  id: string,
  input: { ids: string[] } & Confirmation
) {
  return adminFetch<InstanceScanZone>(`${KEY}/${id}/organizations`, { method: 'PUT', body: input })
}
