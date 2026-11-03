'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'
import type {
  AlertWebhookSettings,
  CaptchaSettings,
  EmailRelayMode,
  EmailRelaySettings,
  MFAFloor,
  MFAFloorSettings,
  PlatformAISettings,
  RegionSettings,
  ScanIdentificationSettings,
  SocialCheckResult,
  SocialLoginSettings,
  StorageQuotaSettings,
  ThreatSourceSettings,
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
const THREAT_SOURCE = '/settings/threat-intel-source'
const SOCIAL = '/settings/social-login-providers'
const MFA_FLOOR = '/settings/auth-mfa'
const EMAIL_RELAY = '/settings/email-relay'
const SCAN_IDENT = '/settings/scan-identification'

export const useCaptchaSettings = () => useSWR<CaptchaSettings>(CAPTCHA, adminFetcher)
export const useRegionSettings = () => useSWR<RegionSettings>(REGION, adminFetcher)
export const useStorageQuota = () => useSWR<StorageQuotaSettings>(QUOTA, adminFetcher)
export const useThreatSource = () => useSWR<ThreatSourceSettings>(THREAT_SOURCE, adminFetcher)
export const useAlertWebhook = () => useSWR<AlertWebhookSettings>(ALERTS, adminFetcher)
export const useSocialLoginSettings = () => useSWR<SocialLoginSettings>(SOCIAL, adminFetcher)
export const usePlatformAI = () => useSWR<PlatformAISettings>(AI, adminFetcher)
export const useMFAFloor = () => useSWR<MFAFloorSettings>(MFA_FLOOR, adminFetcher)
export const useEmailRelay = () => useSWR<EmailRelaySettings>(EMAIL_RELAY, adminFetcher)
export const useScanIdentification = () =>
  useSWR<ScanIdentificationSettings>(SCAN_IDENT, adminFetcher)

/** Step-up and a reason; every administrator is notified. */
export function saveScanIdentification(input: {
  user_agent: string
  user_agent_enforced: boolean
  headers: { name: string; value: string; enforced: boolean }[]
  reason: string
  version: number
}) {
  return adminFetch<ScanIdentificationSettings>(SCAN_IDENT, { method: 'PUT', body: input })
}

/** Super admin, fresh step-up and a reason; raising the floor starts a new grace period. */
export function saveMFAFloor(input: {
  floor: MFAFloor
  grace_days_existing: number
  grace_days_new: number
  reason: string
  version: number
}) {
  return adminFetch<MFAFloorSettings>(MFA_FLOOR, { method: 'PUT', body: input })
}

/** Super admin, fresh step-up and a reason. */
export function saveEmailRelay(input: { mode: EmailRelayMode; reason: string; version: number }) {
  return adminFetch<EmailRelaySettings>(EMAIL_RELAY, { method: 'PUT', body: input })
}

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

/** Where KEV and EPSS come from (super admin and step-up). */
export function saveThreatSource(input: {
  source: 'direct' | 'bundle'
  direct_fetch: 'auto' | 'off'
  version: number
}) {
  return adminFetch<ThreatSourceSettings>(THREAT_SOURCE, { method: 'PUT', body: input })
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
  base_url: string
  allow_private: boolean
  allowed_models: string[]
  api_key?: string
  reason: string
  version: number
}) {
  return adminFetch<PlatformAISettings>(AI, { method: 'PUT', body: input })
}

export function saveOrgAIPolicy(input: {
  allow_org_provider: boolean
  reason: string
  version: number
}) {
  return adminFetch<{ allow_org_provider: boolean; version: number }>(`${AI}/org-policy`, {
    method: 'PUT',
    body: input,
  })
}

export function testPlatformAI() {
  return adminFetch<void>(`${AI}/test`, { method: 'POST' })
}

/** Omit `secret` to keep the stored one; "" removes it. Empty `scopes` use the defaults. */
export function saveSocialProvider(
  provider: string,
  input: {
    enabled: boolean
    client_id: string
    secret?: string
    scopes: string[]
    reason: string
    version: number
  }
) {
  return adminFetch<SocialLoginSettings>(`${SOCIAL}/${provider}`, { method: 'PUT', body: input })
}

/** Asks the provider whether it accepts a client (the one in force when empty). */
export function testSocialProvider(
  provider: string,
  input: { client_id?: string; secret?: string }
) {
  return adminFetch<{ result: SocialCheckResult }>(`${SOCIAL}/${provider}/test`, {
    method: 'POST',
    body: input,
  })
}
