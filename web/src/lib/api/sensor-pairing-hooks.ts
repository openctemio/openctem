/**
 * Interactive sensor pairing, user plane (api docs/rfcs/RFC-052 §4.1, §4.5).
 *
 * A sensor creates its own key and asks to pair; an administrator finds the
 * request by the short code the sensor printed (or creates an expectation and
 * runs `openctemio-sensor pair <CODE>` on the host), compares the fingerprint
 * shown on both sides and approves with step-up re-authentication. No secret
 * passes through the browser: the code and fingerprint are public values.
 *
 * Every route is tenant-scoped by the session. Unknown, expired, used and
 * other-organization codes all answer one 404.
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'

import { useTenant } from '@/context/tenant-provider'
import type { components } from '@/lib/api/generated/api.types'

import { get, post, put } from './client'

type Schemas = components['schemas']

/** A pairing request as the API shows it to this organization. */
export type SensorPairingView =
  Schemas['github_com_openctemio_openctem_api_internal_app_sensorpairing.View']
export type SensorPairingHostFacts =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_sensor.PairingHostFacts']

/** What the approver must present: TOTP, the password, or a recent sign-in. */
export type StepUpMethod = 'totp' | 'password' | 'fresh_sign_in'

export interface StepUpProof {
  totp?: string
  password?: string
}

export interface ApprovePairingRequest {
  /** The code the approver entered (forward mode); not needed for an expectation. */
  code?: string
  fingerprint_confirmed: boolean
  step_up: StepUpProof
  name: string
  type: string
  zone_ids: string[]
  grant_profile: string
}

export interface CreateExpectationRequest {
  name?: string
  zone_ids?: string[]
  grant_profile?: string
  repair_sensor_id?: string
}

export interface SensorIdentityPolicy {
  /** True: new sensors may still get a bearer key. False: pairing only. */
  bearer_keys_allowed: boolean
}

export const SENSOR_PAIRINGS_PATH = '/api/v1/sensor-pairings'
export const SENSOR_IDENTITY_POLICY_PATH = '/api/v1/sensors/identity-policy'

export function lookupPairing(code: string): Promise<SensorPairingView> {
  return post<SensorPairingView>(`${SENSOR_PAIRINGS_PATH}/lookup`, { code })
}

export function createPairingExpectation(
  body: CreateExpectationRequest
): Promise<SensorPairingView> {
  return post<SensorPairingView>(`${SENSOR_PAIRINGS_PATH}/expectations`, body)
}

export function approvePairing(
  id: string,
  body: ApprovePairingRequest
): Promise<SensorPairingView> {
  return post<SensorPairingView>(`${SENSOR_PAIRINGS_PATH}/${encodeURIComponent(id)}/approve`, body)
}

export function rejectPairing(id: string): Promise<void> {
  return post<void>(`${SENSOR_PAIRINGS_PATH}/${encodeURIComponent(id)}/reject`, {})
}

/** Poll interval of an expectation while the dialog waits for the sensor. */
export const EXPECTATION_POLL_MS = 3000

/** Statuses after which a pairing request no longer changes on its own. */
export function pairingSettled(status?: string): boolean {
  return (
    status === 'approved' || status === 'completed' || status === 'denied' || status === 'expired'
  )
}

/**
 * An expectation of this organization, polled until the sensor connected and
 * revealed its nonce (the SAS is then known) or the request settled.
 */
export function usePairingExpectation(id: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  return useSWR<SensorPairingView>(
    currentTenant && id ? `${SENSOR_PAIRINGS_PATH}/expectations/${encodeURIComponent(id)}` : null,
    (url: string) => get<SensorPairingView>(url),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
      refreshInterval: (latest) =>
        latest && (latest.sas || pairingSettled(latest.status)) ? 0 : EXPECTATION_POLL_MS,
      ...config,
    }
  )
}

export function useSensorIdentityPolicy(enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<SensorIdentityPolicy>(
    currentTenant && enabled ? SENSOR_IDENTITY_POLICY_PATH : null,
    (url: string) => get<SensorIdentityPolicy>(url),
    { revalidateOnFocus: false, shouldRetryOnError: false }
  )
}

export function setSensorIdentityPolicy(
  policy: SensorIdentityPolicy
): Promise<SensorIdentityPolicy> {
  return put<SensorIdentityPolicy>(SENSOR_IDENTITY_POLICY_PATH, policy)
}
