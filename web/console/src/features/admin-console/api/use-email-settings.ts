'use client'

import useSWR from 'swr'
import type { EmailSettingsResponse, UpdateEmailSettingsRequest } from '@/lib/api/generated'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'

const KEY = '/settings/email'

/** The platform e-mail (SMTP) settings (System > E-mail). Any administrator reads them; the password never comes back. */
export function useEmailSettings() {
  return useSWR<EmailSettingsResponse>(KEY, adminFetcher)
}

/**
 * Saves the settings (super admin). Omit `password` to keep the stored one;
 * `version` is the version that was read; `totp_code` is a fresh code from the
 * console authenticator.
 */
export function saveEmailSettings(input: UpdateEmailSettingsRequest) {
  return adminFetch<EmailSettingsResponse>(KEY, { method: 'PUT', body: input })
}

/** Sends a test message to the signed-in administrator's own address (super admin). */
export function sendTestEmail() {
  return adminFetch<void>(`${KEY}/test`, { method: 'POST' })
}
