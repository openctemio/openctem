'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'

const FEED_RELAY = '/settings/feed-relay'

export type FeedRelayMode = 'direct' | 'relay'

/** A designated relay sensor. */
export interface FeedRelaySensor {
  id: string
  name?: string
  status?: string
  last_seen_at?: string
  can_relay: boolean
  online: boolean
  last_served_at?: string
  bytes_today: number
}

/** A platform sensor that may (eligible) or may not be designated. */
export interface FeedRelayCandidate {
  id: string
  name: string
  status: string
  last_seen_at?: string
  eligible: boolean
  /** Why it may not relay: inactive or no_capability. */
  reason?: 'inactive' | 'no_capability'
}

export interface FeedRelayRound {
  phase: string
  status: string
  error_code?: string
  refused?: string
  files: number
  delivered: number
  bytes_delivered: number
  bytes_wanted: number
  claimed_by?: string
  claimed_at?: string
  created_at: string
  delivered_at?: string
}

export interface FeedRelayFeed {
  feed: string
  last?: FeedRelayRound
  last_import?: FeedRelayRound
  current?: FeedRelayRound
  applied_sequence?: number
  published_at?: string
  age_seconds?: number
  stale_reason?: string
  stale_detail?: string
}

/** An open administrator alert (relay_offline, feed_stale:<feed>, round_failed:<feed>:<code>). */
export interface FeedRelayAlert {
  key: string
  since: string
}

export interface FeedRelayStatus {
  mode: FeedRelayMode
  /** Why relay mode cannot be chosen: bundle_dir or no_signer. */
  locked?: string
  version: number
  sensor_ids: string[]
  bootstrap?: boolean
  sensors: FeedRelaySensor[]
  feeds: FeedRelayFeed[]
  not_relayed: string[]
  candidates: FeedRelayCandidate[]
  alerts: FeedRelayAlert[]
}

/**
 * How the platform receives its feeds, with the relay's status (any admin).
 * No polling: the status changes over minutes and SWR refreshes it when the
 * page regains focus.
 */
export function useFeedRelay() {
  return useSWR<FeedRelayStatus>(FEED_RELAY, adminFetcher)
}

/**
 * Changes the feed delivery (super admin; the API asks for a fresh
 * authenticator code and audits the change). The mode and the relay sensors
 * are saved together.
 */
export function saveFeedRelay(input: {
  mode: FeedRelayMode
  sensor_ids: string[]
  expected_version: number
}) {
  return adminFetch<FeedRelayStatus>(FEED_RELAY, { method: 'PUT', body: input })
}
