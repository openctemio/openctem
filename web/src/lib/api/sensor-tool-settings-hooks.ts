/**
 * Tool settings (api docs/architecture/sensors.md, "Tool settings"): the
 * organization's defaults per tool (every one of its own sensors) and each
 * sensor's overrides, for each tool whose manifest declares a settings
 * schema. The values reach the sensor inside each signed scan job of the
 * tool. Reads need sensors:read; saving and resetting need sensors:write
 * (setting an Impact option also needs a recent re-authentication). An
 * invalid save answers 422 with every problem by JSON pointer.
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'

import { useTenant } from '@/context/tenant-provider'

import { del, get, put } from './client'
import { ApiClientError } from './error-handler'

export interface ToolSettingsProblem {
  path: string
  message: string
}

export interface SensorToolSettings {
  tool: string
  schema_digest: string
  /** The tool's settings schema (CTIS settings contract). */
  schema: Record<string, unknown>
  /** Stored values; keys left out take their defaults. */
  values: Record<string, unknown>
  stored: boolean
  stored_digest?: string
  /** Why stored values no longer validate after a sensor upgrade. */
  problems: ToolSettingsProblem[]
  /** The organization's defaults this sensor inherits for every key it does not set. */
  organization_values?: Record<string, unknown>
  /** Why the organization's defaults do not fit this sensor's tool (its jobs fail). */
  organization_problems?: ToolSettingsProblem[]
  updated_at?: string
  updated_by?: string
}

/** Where an effective value comes from; "tenant" is the organization's default. */
export type ToolSettingSource = 'default' | 'tenant' | 'sensor' | 'scan' | ''

export interface SensorEffectiveToolSetting {
  key: string
  value: unknown
  source: ToolSettingSource
  flag?: string
  common?: string
  scope: 'sensor' | 'scan'
  tier?: string
  /** Every layer that sets the key, lowest first; the last one is in force. */
  chain?: { source: ToolSettingSource; value: unknown }[]
}

/** One tool's organization defaults. */
export interface ToolDefaults {
  tool: string
  schema_digest: string
  /** The reference schema (newest manifest); null when no sensor reports the tool any more. */
  schema: Record<string, unknown> | null
  values: Record<string, unknown>
  stored: boolean
  /** How many of the organization's own sensors declare settings for the tool. */
  sensors: number
  /** Sensors whose tool version refuses the defaults. */
  problems: { sensor_id: string; sensor_name: string; problems: ToolSettingsProblem[] }[]
  updated_at?: string
  updated_by?: string
}

export interface SensorEffectiveToolSettings {
  tool: string
  schema_digest: string
  items: SensorEffectiveToolSetting[]
}

export const sensorToolSettingsPath = (id: string) =>
  `/api/v1/sensors/${encodeURIComponent(id)}/tool-settings`
export const sensorToolSettingPath = (id: string, tool: string) =>
  `${sensorToolSettingsPath(id)}/${encodeURIComponent(tool)}`

const config: SWRConfiguration = { revalidateOnFocus: false, shouldRetryOnError: false }

export function useSensorToolSettings(sensorId: string | null, enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<{ items: SensorToolSettings[] }>(
    currentTenant && sensorId && enabled ? sensorToolSettingsPath(sensorId) : null,
    (url: string) => get<{ items: SensorToolSettings[] }>(url),
    config
  )
}

export function useSensorEffectiveToolSettings(
  sensorId: string | null,
  tool: string | null,
  enabled = true
) {
  const { currentTenant } = useTenant()
  return useSWR<SensorEffectiveToolSettings>(
    currentTenant && sensorId && tool && enabled
      ? `${sensorToolSettingPath(sensorId, tool)}/effective`
      : null,
    (url: string) => get<SensorEffectiveToolSettings>(url),
    config
  )
}

export const toolDefaultsPath = '/api/v1/sensors/tool-defaults'
export const toolDefaultPath = (tool: string) => `${toolDefaultsPath}/${encodeURIComponent(tool)}`

export function useToolDefaults(enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<{ items: ToolDefaults[] }>(
    currentTenant && enabled ? toolDefaultsPath : null,
    (url: string) => get<{ items: ToolDefaults[] }>(url),
    config
  )
}

export function saveToolDefaults(
  tool: string,
  values: Record<string, unknown>
): Promise<ToolDefaults> {
  return put<ToolDefaults>(toolDefaultPath(tool), { values })
}

export function resetToolDefaults(tool: string): Promise<void> {
  return del<void>(toolDefaultPath(tool))
}

export function saveSensorToolSettings(
  sensorId: string,
  tool: string,
  values: Record<string, unknown>
): Promise<SensorToolSettings> {
  return put<SensorToolSettings>(sensorToolSettingPath(sensorId, tool), { values })
}

export function resetSensorToolSettings(sensorId: string, tool: string): Promise<void> {
  return del<void>(sensorToolSettingPath(sensorId, tool))
}

/** The problems of a 422 answer to a save, or []. */
export function toolSettingsProblems(err: unknown): ToolSettingsProblem[] {
  if (!(err instanceof ApiClientError) || err.statusCode !== 422) return []
  const details: unknown = err.details
  if (!Array.isArray(details)) return []
  return details.filter(
    (d): d is ToolSettingsProblem =>
      typeof d === 'object' &&
      d !== null &&
      typeof (d as ToolSettingsProblem).path === 'string' &&
      typeof (d as ToolSettingsProblem).message === 'string'
  )
}
