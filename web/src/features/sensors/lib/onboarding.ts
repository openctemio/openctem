/**
 * Pure helpers of the "Add sensor" panel (api docs/architecture/sensor-pairing.md,
 * "Onboarding"): where the sensor runs, how it joins, where the pairing is,
 * and what to do when the sensor's log says something went wrong.
 */

import type { SensorPairingView } from '@/lib/api/sensor-pairing-hooks'

import { pairingSettled } from '@/lib/api/sensor-pairing-hooks'
import type { SensorTemplates } from '../components/sensor-install-snippets'

/** Where the sensor runs: one tab each. */
export type OnboardingPlatform = 'docker' | 'compose' | 'kubernetes' | 'linux'

export interface OnboardingPlatformOption {
  key: OnboardingPlatform
  labelKey: string
  /** The field of the install-templates answer that holds this platform's commands. */
  field: keyof Pick<SensorTemplates, 'docker' | 'compose' | 'kubernetes' | 'cli'>
  /** File name offered for download, when the snippet is a file. */
  file?: string
}

export const ONBOARDING_PLATFORMS: OnboardingPlatformOption[] = [
  { key: 'docker', labelKey: 'sensors.onboard.platform.docker', field: 'docker' },
  {
    key: 'compose',
    labelKey: 'sensors.onboard.platform.compose',
    field: 'compose',
    file: 'compose.yaml',
  },
  {
    key: 'kubernetes',
    labelKey: 'sensors.onboard.platform.kubernetes',
    field: 'kubernetes',
    file: 'openctem-sensor.yaml',
  },
  { key: 'linux', labelKey: 'sensors.onboard.platform.linux', field: 'cli' },
]

/** How the sensor joins the organization. */
export type JoinMethod = 'code' | 'interactive'

/**
 * Where a "create a pairing code first" pairing stands, in the order the
 * administrator sees it: no code yet, waiting for the sensor, the sensor is
 * attached (compare the fingerprint and approve), approved (the sensor
 * confirms), online (it called home with its new identity). `ended` is a
 * code that expired or was refused before anything was approved.
 */
export type OnboardingStage = 'start' | 'waiting' | 'compare' | 'approved' | 'online' | 'ended'

export const ONBOARDING_STAGES: OnboardingStage[] = ['waiting', 'compare', 'approved', 'online']

export function onboardingStage(
  view: SensorPairingView | null | undefined,
  opts: { approvedSensorId?: string | null; sensorSeen?: boolean; now: number }
): OnboardingStage {
  if (opts.approvedSensorId) return opts.sensorSeen ? 'online' : 'approved'
  if (!view) return 'start'
  if (view.status === 'approved' || view.status === 'completed') {
    return opts.sensorSeen ? 'online' : 'approved'
  }
  if (view.status === 'denied' || view.status === 'expired') return 'ended'
  const exp = view.expires_at ? Date.parse(view.expires_at) : NaN
  if (!Number.isNaN(exp) && exp <= opts.now) return 'ended'
  if (view.sas && !pairingSettled(view.status)) return 'compare'
  return 'waiting'
}

/** The index of a stage in the stepper (-1 before the first). */
export function stageIndex(stage: OnboardingStage): number {
  return ONBOARDING_STAGES.indexOf(stage)
}

/**
 * Problems a first install runs into, each keyed by what the sensor prints.
 * `lines` are the sensor's own log lines (English, as the sensor writes them;
 * matched by their start), shown verbatim so the reader can find them in the
 * log. The title and fix are catalog keys.
 */
export interface TroubleshootingItem {
  key: string
  lines: string[]
}

export const TROUBLESHOOTING: TroubleshootingItem[] = [
  {
    key: 'noCode',
    lines: ['Pair this sensor in OpenCTEM'],
  },
  {
    key: 'expired',
    lines: [
      'pairing: the request expired before it was approved',
      'The pairing request expired; starting a new one.',
    ],
  },
  {
    key: 'clock',
    lines: ['clock', 'pairing: start: unauthenticated'],
  },
  {
    key: 'rateLimited',
    lines: ['429', 'Too Many Requests'],
  },
  {
    key: 'unreachable',
    lines: ['dial tcp', 'x509: certificate signed by unknown authority', 'proxyconnect tcp'],
  },
  {
    key: 'policy',
    lines: ['SENSOR_LOCAL_POLICY'],
  },
  {
    key: 'denied',
    lines: ['pairing: an administrator refused this sensor'],
  },
]

/** The URL a host checks it can reach (the API's health route). */
export function healthCheckCommand(apiURL: string | undefined): string {
  const base = (apiURL ?? '').replace(/\/+$/, '')
  return base ? `curl -fsS ${shellQuote(`${base}/health`)}` : ''
}

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`
}
