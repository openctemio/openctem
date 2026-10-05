'use client'

import useSWR from 'swr'
import { get, post, put } from '@/lib/api/client'
import type { EASMSettings, EASMSweepTicket } from '@/lib/api/generated'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'

export const EASM_SETTINGS_KEY = '/api/v1/easm/settings'

/**
 * GET /api/v1/easm/settings (research/22 P0-11): whether the Certificate
 * Transparency monitor and the DNS checks run for the organization, their
 * cadence and when each last ran. Fetched only with settings:read and the
 * attack_surface module.
 */
export function useEASMSettings() {
  const { can } = usePermissions()
  const { moduleIds, isLoading: modulesLoading } = useTenantModules()
  const enabled =
    can(Permission.SettingsRead) && !modulesLoading && moduleIds.includes('attack_surface')
  const { data, error, isLoading, mutate } = useSWR<EASMSettings>(
    enabled ? EASM_SETTINGS_KEY : null,
    get,
    { revalidateOnFocus: false }
  )
  return { settings: data, error, isLoading: isLoading || modulesLoading, mutate, enabled }
}

export interface EASMSettingsInput {
  ct_enabled: boolean
  dns_checks_enabled: boolean
  /** 0 = platform default; otherwise 6..168. */
  ct_interval_hours: number
  dns_interval_hours: number
}

/** PUT /api/v1/easm/settings (settings:write, audited). */
export function saveEASMSettings(input: EASMSettingsInput) {
  return put<EASMSettings>(EASM_SETTINGS_KEY, input)
}

/** POST /api/v1/easm/sweeps: at most once per 15 minutes (429 otherwise). */
export function runEASMSweep() {
  return post<EASMSweepTicket>('/api/v1/easm/sweeps', {})
}
