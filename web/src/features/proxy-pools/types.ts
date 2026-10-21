/**
 * Sensor proxy pools: the wire shapes of /api/v1/proxy-pools. Credentials are
 * write-only: no response carries them, `endpoints_text` shows them as the
 * mask.
 */

export type ProxyStrategy = 'sticky' | 'priority'
export type ProxyHealthState = 'healthy' | 'probation' | 'quarantined'
export type ProxyAssignmentMode = 'inherit' | 'direct' | 'pool'

export interface ProxyEndpointHealth {
  state: ProxyHealthState
  /** 0 to 1. */
  score: number
  consecutive_failures: number
  ok_total: number
  fail_total: number
  handshake_ms_p95: number
  last_error: string
  last_ok_at: string | null
  last_failure_at: string | null
  quarantined_until: string | null
}

export interface ProxyEndpoint {
  id: string
  scheme: 'http' | 'https' | 'socks5' | 'socks5h'
  host: string
  port: number
  label: string
  priority: number
  enabled: boolean
  has_credentials: boolean
  credentials_updated_at?: string | null
  health: ProxyEndpointHealth
}

export interface ProxyPool {
  id: string
  name: string
  description: string
  enabled: boolean
  is_default: boolean
  strategy: ProxyStrategy
  revision: number
  assigned_sensors: number
  created_at: string
  updated_at: string
  endpoints_text: string
  endpoints: ProxyEndpoint[]
}

export interface ProxyPoolList {
  items: ProxyPool[]
}

export interface CreateProxyPoolRequest {
  name: string
  description?: string
  strategy?: ProxyStrategy
  enabled?: boolean
  is_default?: boolean
  endpoints_text?: string
}

export interface UpdateProxyPoolRequest {
  name?: string
  description?: string
  strategy?: ProxyStrategy
  enabled?: boolean
  is_default?: boolean
}

export interface UpdateProxyEndpointRequest {
  enabled?: boolean
  reset_health?: boolean
}

export interface ProxyAssignment {
  sensor_id: string
  mode: ProxyAssignmentMode
  pool_id?: string | null
}

export interface ProxyAssignmentList {
  items: ProxyAssignment[]
}

export interface SetProxyAssignmentRequest {
  mode: ProxyAssignmentMode
  pool_id?: string
}
