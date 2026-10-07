/**
 * Platform scanning: GET /api/v1/platform/scanning.
 *
 * The platform operator's shared sensors as the organization sees them: a
 * managed service with regions and a state, the tools it runs and the
 * organization's own platform jobs. Never a sensor (no id, name, host,
 * address or version) and nothing about other organizations. Platform
 * sensors are managed from the admin console only.
 */

/** available: a free slot now; busy: every slot taken, jobs wait; unavailable: nothing online. */
export type PlatformScanningStatus = 'available' | 'busy' | 'unavailable'

export interface PlatformRegion {
  /** The operator's region label; empty when the operator set none. */
  name: string
  status: PlatformScanningStatus
}

export interface PlatformScanningResponse {
  /** The organization may send scans to platform scanning. False says nothing else. */
  offered: boolean
  /** The best region's state; absent when not offered. */
  status?: PlatformScanningStatus
  regions: PlatformRegion[]
  /** Tools platform scanning runs now. */
  tools: string[]
  /** The organization's own platform jobs. */
  your_jobs: { queued: number; running: number }
  /** A platform job that waits this long for a slot fails. */
  queue_limit_minutes?: number
}
