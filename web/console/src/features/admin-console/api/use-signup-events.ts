'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'

/**
 * The sign-up feed (docs/architecture/signup-activity.md): accounts created,
 * organizations created and access requests submitted, as registrable email
 * domain and client network prefix only. Any administrator reads it.
 */
export type SignupEventKind = 'account_created' | 'organization_created' | 'access_requested'

export const SIGNUP_EVENT_KINDS: SignupEventKind[] = [
  'account_created',
  'organization_created',
  'access_requested',
]

export interface SignupEvent {
  id: number
  kind: SignupEventKind
  source: string
  email_domain?: string
  ip_prefix?: string
  tenant_id?: string
  occurred_at: string
}

export interface SignupEventList {
  data: SignupEvent[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export interface SignupDailyCount {
  day: string
  kind: SignupEventKind
  count: number
}

export const SIGNUP_EVENTS_PER_PAGE = 50

/** A page of the feed, newest first. Empty kind: every kind. */
export function useSignupEvents(kind: SignupEventKind | '', page: number) {
  const qs = new URLSearchParams({ page: String(page), per_page: String(SIGNUP_EVENTS_PER_PAGE) })
  if (kind) qs.set('kind', kind)
  return useSWR<SignupEventList>(`/signup-events?${qs.toString()}`, adminFetcher, {
    keepPreviousData: true,
  })
}

/** Events per kind per UTC day for the last `days` days. */
export function useSignupDaily(days: number) {
  return useSWR<SignupDailyCount[]>(`/signup-events/daily?days=${days}`, adminFetcher)
}

/** Burst alert thresholds; 0 turns a dimension off. */
export interface SignupAlertThresholds {
  per_ip_prefix: number
  per_email_domain: number
  window_minutes: number
  ignored_domains: string[]
}

export interface SignupAlerts extends SignupAlertThresholds {
  version: number
}

const ALERTS_KEY = '/settings/signup-alerts'

export function useSignupAlerts() {
  return useSWR<SignupAlerts>(ALERTS_KEY, adminFetcher)
}

/** Super admin, a reason and a fresh authenticator code. */
export function saveSignupAlerts(
  input: SignupAlertThresholds & { version: number; reason: string; totp_code: string }
) {
  return adminFetch<SignupAlerts>(ALERTS_KEY, { method: 'PUT', body: input })
}
