/**
 * Scan Types
 *
 * Type definitions for scan management
 */

import type { Status } from '@/features/shared/types'

// ============================================
// SCAN TYPE
// ============================================

export type ScanType = 'full' | 'quick' | 'custom' | 'compliance'

// ============================================
// SCAN MODE (Single vs Workflow)
// ============================================

export type ScanMode = 'single' | 'workflow'

export const SCAN_MODE_CONFIG: Record<
  ScanMode,
  { label: string; description: string; icon: string }
> = {
  single: {
    label: 'Single Scan',
    description: 'Run a one-time scan with custom configuration',
    icon: 'radar',
  },
  workflow: {
    label: 'Workflow Scan',
    description: 'Use a predefined workflow with multiple scan tools',
    icon: 'git-branch',
  },
}

// ============================================
// SENSOR PREFERENCE (Platform Sensor Selection)
// ============================================

export type SensorPreference = 'auto' | 'tenant' | 'platform'

export const SENSOR_PREFERENCE_CONFIG: Record<
  SensorPreference,
  { label: string; description: string; icon: string }
> = {
  auto: {
    label: 'Auto',
    description: 'System selects the best available sensor automatically',
    icon: 'sparkles',
  },
  tenant: {
    label: 'Your sensors',
    description: "Use only your organization's deployed sensors",
    icon: 'server',
  },
  platform: {
    label: 'Platform scanning',
    description: "Use the platform's shared scanning (public targets only)",
    icon: 'cloud',
  },
}

export const SCAN_TYPE_LABELS: Record<ScanType, string> = {
  full: 'Full Scan',
  quick: 'Quick Scan',
  custom: 'Custom',
  compliance: 'Compliance',
}

// ============================================
// SCAN OPTIONS
// ============================================

export interface ScanOptions {
  portScanning: boolean
  webAppScanning: boolean
  sslAnalysis: boolean
  bruteForce: boolean
  techDetection: boolean
  apiSecurity: boolean
}

// ============================================
// INTENSITY
// ============================================

export type ScanIntensity = 'low' | 'medium' | 'high'

// ============================================
// SCHEDULE
// ============================================

export type ScheduleFrequency = 'once' | 'daily' | 'weekly' | 'monthly'

export interface ScanSchedule {
  runImmediately: boolean
  frequency?: ScheduleFrequency
  dayOfWeek?: number // 0 = Sunday, 1 = Monday, etc.
  /** Monthly: day of the month, 1-31 (a shorter month runs on its last day). */
  dayOfMonth?: number
  time?: string // "02:00" format
  /** Once: the run's date (YYYY-MM-DD) and time (HH:MM) in `timezone`. */
  runAtDate?: string
  runAtTime?: string
  /** IANA zone the schedule is in; empty = the viewer's zone. */
  timezone?: string
}

export const FREQUENCY_OPTIONS: { value: ScheduleFrequency; label: string }[] = [
  { value: 'once', label: 'Once' },
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' },
]

export const DAY_OPTIONS = [
  { value: 0, label: 'Sunday' },
  { value: 1, label: 'Monday' },
  { value: 2, label: 'Tuesday' },
  { value: 3, label: 'Wednesday' },
  { value: 4, label: 'Thursday' },
  { value: 5, label: 'Friday' },
  { value: 6, label: 'Saturday' },
]

export const TIME_OPTIONS = Array.from({ length: 24 }, (_, i) => ({
  value: `${i.toString().padStart(2, '0')}:00`,
  label: `${i.toString().padStart(2, '0')}:00`,
}))

// ============================================
// NOTIFICATIONS
// ============================================

export interface ScanNotifications {
  notifyOnComplete: boolean
  autoCreateTasks: boolean
}

export const DEFAULT_NOTIFICATIONS: ScanNotifications = {
  notifyOnComplete: true,
  autoCreateTasks: true,
}

// ============================================
// TARGET SELECTION
// ============================================

export type TargetType = 'asset_groups' | 'individual' | 'custom'

export interface ScanTargets {
  type: TargetType
  assetGroupIds: string[]
  assetIds: string[]
  /** Asset names by id: what the picker shows and the previews check (the request sends the ids). */
  assetNames: Record<string, string>
  /** Asset group names by id, for the selection chips. */
  assetGroupNames?: Record<string, string>
  customTargets: string[] // domains, IPs
  /**
   * How far typed domains reach (research/48 §6.7): the names themselves, plus
   * their inventory subdomains, plus the addresses those resolved to.
   */
  coverage?: 'host' | 'subdomains' | 'subdomains_ips'
  /** Targets the coverage level added (sent with the others; each one is gated). */
  expandedTargets?: string[]
}

export const DEFAULT_TARGETS: ScanTargets = {
  type: 'asset_groups',
  assetGroupIds: [],
  assetIds: [],
  assetNames: {},
  customTargets: [],
  coverage: 'host',
  expandedTargets: [],
}

// ============================================
// NEW SCAN FORM DATA
// ============================================

export interface NewScanFormData {
  // Step 1: Basic Info
  name: string
  mode: ScanMode
  /** Tool registry name of the scanner (mode "single"); the API requires it. */
  scannerName: string
  workflowId?: string // Workflow template id, only when mode is "workflow"
  /**
   * scanner_config of a scanner that needs one: a connector scanner
   * (tenable_sc: the connector integration, policy and repository). Other
   * scanners take their settings from the scan profile.
   */
  scannerConfig?: Record<string, unknown>
  sensorPreference: SensorPreference // Platform sensor selection
  profileId?: string // Optional scan profile (drives quality gate evaluation)

  // Step 2: Targets
  targets: ScanTargets

  // Step 3: Options
  /** Targets bundled into one job (API targets_per_job). */
  maxConcurrent: number
  /** Max execution time in seconds (30-86400, default 3600) */
  timeoutSeconds: number
  /** Max automatic retry attempts after failure (0-10, default 0) */
  maxRetries: number
  /** Initial backoff between retries in seconds (10-86400, default 60) */
  retryBackoffSeconds: number

  // Step 4: Schedule
  schedule: ScanSchedule
  notifications: ScanNotifications

  /** Scan zone the scan is restricted to; null/undefined = Automatic (RFC-023). */
  scanZoneId?: string | null
}

export const DEFAULT_NEW_SCAN: NewScanFormData = {
  name: '',
  mode: 'single',
  scannerName: '',
  workflowId: undefined,
  sensorPreference: 'auto',
  profileId: undefined,
  targets: DEFAULT_TARGETS,
  maxConcurrent: 10,
  timeoutSeconds: 3600,
  maxRetries: 0,
  retryBackoffSeconds: 60,
  schedule: {
    runImmediately: true,
    frequency: 'weekly',
    dayOfWeek: 1,
    time: '02:00',
  },
  notifications: DEFAULT_NOTIFICATIONS,
  scanZoneId: null,
}

// ============================================
// SENSOR TYPE (tenant vs platform)
// ============================================

export type SensorType = 'tenant' | 'platform'

export const SENSOR_TYPE_CONFIG: Record<
  SensorType,
  { label: string; description: string; color: string }
> = {
  tenant: {
    label: 'Your Sensor',
    description: "Running on your organization's deployed sensor",
    color: 'blue',
  },
  platform: {
    label: 'Platform Sensor',
    description: "Running on OpenCTEM's managed cloud infrastructure",
    color: 'purple',
  },
}

// ============================================
// SCAN ENTITY (for listing)
// ============================================

export interface Scan {
  id: string
  name: string
  description?: string
  type: ScanType
  status: Status
  targets: ScanTargets
  targetCount: number
  progress: number // 0-100
  options: ScanOptions
  intensity: ScanIntensity
  maxConcurrent: number
  findingsCount: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  startedAt?: string
  completedAt?: string
  duration?: number // in seconds
  schedule: ScanSchedule
  notifications: ScanNotifications
  createdBy: string
  createdByName: string
  createdAt: string
  updatedAt: string

  // Platform sensor fields
  sensorPreference: SensorPreference
  sensorType?: SensorType // Actual sensor type assigned
  sensorId?: string // Sensor ID if assigned
  sensorName?: string // Sensor name for display
  queuePosition?: number // Position in queue (for platform jobs)
}

// ============================================
// SCAN STATISTICS
// ============================================

export interface ScanStats {
  totalScans: number
  activeScans: number
  completedScans: number
  failedScans: number
  scheduledScans: number
  totalFindings: number
  averageDuration: number
}

// ============================================
// SMART FILTERING (Asset-Scanner Compatibility)
// ============================================

/**
 * Preview of asset compatibility before scan creation
 * Used to warn users about incompatible assets in the selected group
 */
export interface AssetCompatibilityPreview {
  /** Total assets in selected asset group(s) */
  totalAssets: number
  /** Assets compatible with the selected tool */
  compatibleAssets: number
  /** Assets incompatible with the selected tool */
  incompatibleAssets: number
  /** Unclassified assets that cannot be matched */
  unclassifiedAssets: number
  /** Percentage of compatible assets (0-100) */
  compatibilityPercent: number
  /** Breakdown by asset type with compatibility status */
  assetTypeBreakdown?: AssetTypeCompatibility[]
  /** Tool name for context */
  toolName?: string
  /** Target types supported by the tool */
  supportedTargets?: string[]
}

/**
 * Asset type compatibility info for preview
 */
export interface AssetTypeCompatibility {
  assetType: string
  count: number
  isCompatible: boolean
  reason?: string
}

/**
 * Compatibility status for UI display
 */
export type CompatibilityStatus = 'full' | 'partial' | 'none'

/**
 * Get compatibility status from percentage
 */
export function getCompatibilityStatus(percent: number): CompatibilityStatus {
  if (percent >= 100) return 'full'
  if (percent > 0) return 'partial'
  return 'none'
}

/**
 * Get color config for compatibility status
 */
export const COMPATIBILITY_STATUS_CONFIG: Record<
  CompatibilityStatus,
  { label: string; color: string; bgColor: string; textColor: string; icon: string }
> = {
  full: {
    label: 'Fully Compatible',
    color: 'green',
    bgColor: 'bg-green-500/15',
    textColor: 'text-green-600',
    icon: 'CheckCircle',
  },
  partial: {
    label: 'Partially Compatible',
    color: 'yellow',
    bgColor: 'bg-yellow-500/15',
    textColor: 'text-yellow-600',
    icon: 'AlertTriangle',
  },
  none: {
    label: 'Not Compatible',
    color: 'red',
    bgColor: 'bg-red-500/15',
    textColor: 'text-red-600',
    icon: 'XCircle',
  },
}
