import type { SensorLocalPolicy } from '@/lib/api/sensor-types'

/** How the console presents a sensor's local policy state. */
export interface LocalPolicyView {
  label: string
  tone: 'ok' | 'warn' | 'danger' | 'muted'
  description: string
}

/**
 * The view of a sensor-local policy (api RFC-040 §5.7). The policy is written
 * by the network owner on the sensor host and enforced there; the platform
 * only shows what the sensor reports.
 */
export function localPolicyView(p?: SensorLocalPolicy | null): LocalPolicyView {
  switch (p?.state) {
    case 'enforced':
      return {
        label: 'Enforced',
        tone: 'ok',
        description:
          'The network owner installed a local policy. The sensor refuses every job outside it.',
      }
    case 'paused':
      return {
        label: 'Paused (kill switch)',
        tone: 'danger',
        description:
          'The sensor owner engaged the local kill switch: the sensor runs no job until it is released.',
      }
    case 'absent':
      return {
        label: 'Absent',
        tone: 'warn',
        description:
          'No local policy: the sensor runs any target outside its built-in deny list. Install one from the Install tab.',
      }
    default:
      return {
        label: 'Not reported',
        tone: 'muted',
        description: 'This sensor runs an SDK that does not report a local policy.',
      }
  }
}

/** The first 12 hex characters of a "sha256:<hex>" digest. */
export function shortPolicyDigest(digest?: string): string {
  if (!digest) return ''
  const hex = digest.startsWith('sha256:') ? digest.slice(7) : digest
  return hex.slice(0, 12)
}

/** One-line summary of an enforced policy's shape, never its ranges. */
export function localPolicySummaryLines(p?: SensorLocalPolicy | null): string[] {
  const s = p?.summary
  if (!s) return []
  const lines: string[] = []
  lines.push(
    s.targets_allow < 0
      ? `Targets: any outside ${s.targets_deny} denied entr${s.targets_deny === 1 ? 'y' : 'ies'}`
      : `Targets: ${s.targets_allow} allowed, ${s.targets_deny} denied`
  )
  lines.push(`Private ranges: ${s.allow_private ? 'allowed' : 'refused'}`)
  lines.push(`Ports: ${s.ports ? s.ports : 'any'}`)
  if (s.tools) lines.push(`Tools: ${s.tools.length ? s.tools.join(', ') : 'none'}`)
  if (s.checks) lines.push(`Job types: ${s.checks.length ? s.checks.join(', ') : 'none'}`)
  lines.push(`Custom templates: ${s.allow_custom_templates ? 'allowed' : 'refused'}`)
  lines.push(`Interactsh callbacks: ${s.allow_interactsh ? 'allowed' : 'refused'}`)
  if (s.max_rps) lines.push(`Rate: at most ${s.max_rps} requests/s`)
  if (s.max_job_seconds) lines.push(`Job time: at most ${s.max_job_seconds} s`)
  return lines
}
