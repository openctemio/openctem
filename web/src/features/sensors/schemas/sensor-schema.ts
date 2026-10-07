import { z } from 'zod'

// Sensor type options (CTEM framework)
// Legacy v1 type values (RFC-023 §9.1). "Sensor" is now the umbrella term, so
// the old 'sensor' type (an EASM vantage point) is labelled External (EASM).
// worker = daemon, collector = asset discovery, sensor = EASM. CI pipelines are
// not sensors: they use their CI provider's OIDC identity (api RFC-051).
export const SENSOR_TYPE_OPTIONS = [
  { value: 'worker', label: 'Worker', description: 'Long-running daemon worker' },
  { value: 'collector', label: 'Collector', description: 'Asset discovery collector' },
  { value: 'sensor', label: 'External (EASM)', description: 'Internet-facing EASM vantage point' },
] as const

// Sensor health options (heartbeat-based, automatic)
export const SENSOR_HEALTH_OPTIONS = [
  { value: 'unknown', label: 'Unknown' },
  { value: 'online', label: 'Online' },
  { value: 'offline', label: 'Offline' },
  { value: 'error', label: 'Error' },
] as const

// Execution mode options
export const SENSOR_EXECUTION_MODE_OPTIONS = [
  { value: 'standalone', label: 'Standalone' },
  { value: 'daemon', label: 'Daemon' },
] as const

// Note: capability options are loaded from the API.
// The tools a sensor has come from its own report, never from a form.

// Enum schemas
export const sensorTypeSchema = z.enum(['worker', 'collector', 'sensor'])
export const sensorStatusSchema = z.enum(['active', 'disabled', 'revoked'])
export const sensorHealthSchema = z.enum(['unknown', 'online', 'offline', 'error'])
export const executionModeSchema = z.enum(['standalone', 'daemon'])

// Create sensor form data type (for form)
export interface CreateSensorFormData {
  name: string
  type: 'worker' | 'collector' | 'sensor'
  description?: string
  capabilities: string[]
  execution_mode: 'standalone' | 'daemon'
  labels?: Record<string, string>
}

// Create sensor schema
export const createSensorSchema = z.object({
  name: z.string().min(1, 'Name is required').max(255, 'Name must be less than 255 characters'),
  type: sensorTypeSchema,
  description: z.string().max(1000).optional(),
  capabilities: z.array(z.string()),
  execution_mode: executionModeSchema,
  labels: z.record(z.string(), z.string()).optional(),
})
