'use client'

import useSWR from 'swr'
import type { LegalSettingsResponse, UpdateLegalSettingsRequest } from '@/lib/api/generated'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'

const KEY = '/settings/legal'

/** The operator's legal information (System > Legal). Any administrator reads it. */
export function useLegalSettings() {
  return useSWR<LegalSettingsResponse>(KEY, adminFetcher)
}

/** Saves it (super admin, fresh authenticator code, the version that was read). */
export function saveLegalSettings(input: UpdateLegalSettingsRequest) {
  return adminFetch<LegalSettingsResponse>(KEY, { method: 'PUT', body: input })
}
