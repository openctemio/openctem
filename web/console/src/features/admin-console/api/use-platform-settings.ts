'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'
import type {
  AlertWebhookSettings,
  CaptchaSettings,
  PlatformAISettings,
  RegionSettings,
  StorageQuotaSettings,
} from '../types'

/*
 * The settings that moved from server environment variables into the
 * console (RFC-079). Any administrator reads them; secrets never come back.
 * Changes need a super admin and the console step-up (adminFetch asks for
 * it); the guarded ones also need a reason.
 */

const CAPTCHA = '/settings/captcha'
const REGION = '/settings/region'
const QUOTA = '/settings/storage-quota'
const ALERTS = '/settings/alerts'
const AI = '/settings/ai'

export const useCaptchaSettings = () => useSWR<CaptchaSettings>(CAPTCHA, adminFetcher)
export const useRegionSettings = () => useSWR<RegionSettings>(REGION, adminFetcher)
export const useStorageQuota = () => useSWR<StorageQuotaSettings>(QUOTA, adminFetcher)
export const useAlertWebhook = () => useSWR<AlertWebhookSettings>(ALERTS, adminFetcher)
export const usePlatformAI = () => useSWR<PlatformAISettings>(AI, adminFetcher)

/** Omit `secret` to keep the stored one; "" removes it. */
export function saveCaptcha(input: {
  site_key: string
  secret?: string
  reason: string
  version: number
}) {
  return adminFetch<CaptchaSettings>(CAPTCHA, { method: 'PUT', body: input })
}

/** Asks Turnstile whether it accepts a secret (the one in force when empty). */
export function verifyCaptchaSecret(secret?: string) {
  return adminFetch<{ result: 'valid' | 'invalid' | 'unreachable' }>(`${CAPTCHA}/verify`, {
    method: 'POST',
    body: secret ? { secret } : {},
  })
}

/** Sets the region once, before the first organization exists. */
export function setRegion(input: { region: string; reason: string }) {
  return adminFetch<RegionSettings>(REGION, { method: 'PUT', body: input })
}

export function saveStorageQuota(input: { default_mb: number; version: number }) {
  return adminFetch<StorageQuotaSettings>(QUOTA, { method: 'PUT', body: input })
}

/** Omit `url` or `secret` to keep the stored value; "" removes it. */
export function saveAlertWebhook(input: {
  enabled: boolean
  url?: string
  secret?: string
  reason: string
  version: number
}) {
  return adminFetch<AlertWebhookSettings>(ALERTS, { method: 'PUT', body: input })
}

export function sendTestAlert() {
  return adminFetch<void>(`${ALERTS}/test`, { method: 'POST' })
}

/** Omit `api_key` to keep the stored key; "" removes it. */
export function savePlatformAI(input: {
  enabled: boolean
  provider: string
  model: string
  api_key?: string
  reason: string
  version: number
}) {
  return adminFetch<PlatformAISettings>(AI, { method: 'PUT', body: input })
}

export function testPlatformAI() {
  return adminFetch<void>(`${AI}/test`, { method: 'POST' })
}
