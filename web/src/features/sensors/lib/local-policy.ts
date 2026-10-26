import type { SensorLocalPolicy } from '@/lib/api/sensor-types'

import type { Tr } from './format'

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
export function localPolicyView(p?: SensorLocalPolicy | null, tr?: Tr): LocalPolicyView {
  const pick = (key: string, english: string) => (tr ? tr(key) : english)
  switch (p?.state) {
    case 'enforced':
      return {
        label: pick('sensors.localPolicy.label.enforced', 'Enforced'),
        tone: 'ok',
        description: pick(
          'sensors.localPolicy.desc.enforced',
          'The network owner installed a local policy. The sensor refuses every job outside it.'
        ),
      }
    case 'paused':
      return {
        label: pick('sensors.localPolicy.label.paused', 'Paused (kill switch)'),
        tone: 'danger',
        description: pick(
          'sensors.localPolicy.desc.paused',
          'The sensor owner engaged the local kill switch: the sensor runs no job until it is released.'
        ),
      }
    case 'absent':
      if (p?.required) {
        return {
          label: pick('sensors.localPolicy.label.absentRequired', 'Absent (network jobs refused)'),
          tone: 'danger',
          description: pick(
            'sensors.localPolicy.desc.absentRequired',
            'This sensor requires a local policy and has none: it refuses every job with a network target until the network owner installs one.'
          ),
        }
      }
      return {
        label: pick('sensors.localPolicy.label.absent', 'Absent'),
        tone: 'warn',
        description: pick(
          'sensors.localPolicy.desc.absent',
          'No local policy: the sensor runs any target outside its built-in deny list. Install one from the Install tab.'
        ),
      }
    default:
      return {
        label: pick('sensors.localPolicy.label.notReported', 'Not reported'),
        tone: 'muted',
        description: pick(
          'sensors.localPolicy.desc.notReported',
          'This sensor runs an SDK that does not report a local policy.'
        ),
      }
  }
}

/**
 * What a sensor without a local policy really allows, and who decides
 * (api research/25 §2.2). Sensor v0.9.x warns that custom templates and
 * interactsh "are allowed"; in practice custom templates are refused unless
 * SENSOR_TEMPLATE_SIGNING_KEYS is set on the host, interactsh runs only when
 * a job asks for it, and the platform sends neither unless the organization
 * turned it on. Shown next to the sensor's own warning.
 */
export function noLocalPolicyGuidance(tr?: Tr): string[] {
  const pick = (key: string, english: string) => (tr ? tr(key) : english)
  return [
    pick(
      'sensors.localPolicy.guidance.1',
      'Custom templates: refused by the sensor unless SENSOR_TEMPLATE_SIGNING_KEYS is set on the host, and sent by the platform only when your organization allows custom templates.'
    ),
    pick(
      'sensors.localPolicy.guidance.2',
      'Out-of-band callbacks (interactsh): used only by a job that asks for them, and the platform sends such jobs only when your organization allows interactsh.'
    ),
    pick(
      'sensors.localPolicy.guidance.3',
      'To decide on the host, install /etc/openctem/sensor-policy.yaml with allow_custom_templates and allow_interactsh (the Install tab renders one with both off).'
    ),
  ]
}

/** Whether the sensor's warnings include the absent-policy warning. */
export function hasNoLocalPolicyWarning(p?: SensorLocalPolicy | null): boolean {
  return (p?.warnings ?? []).some((w) => w.toLowerCase().startsWith('no local policy'))
}

/** The first 12 hex characters of a "sha256:<hex>" digest. */
export function shortPolicyDigest(digest?: string): string {
  if (!digest) return ''
  const hex = digest.startsWith('sha256:') ? digest.slice(7) : digest
  return hex.slice(0, 12)
}

/** One-line summary of an enforced policy's shape, never its ranges. */
export function localPolicySummaryLines(p?: SensorLocalPolicy | null, tr?: Tr): string[] {
  if (tr) return localizedSummaryLines(p, tr)
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

function localizedSummaryLines(p: SensorLocalPolicy | null | undefined, tr: Tr): string[] {
  const s = p?.summary
  if (!s) return []
  const allowed = (on: boolean) =>
    tr(on ? 'sensors.localPolicy.sum.allowed' : 'sensors.localPolicy.sum.refused')
  const none = tr('sensors.localPolicy.sum.none')
  const lines: string[] = []
  lines.push(
    s.targets_allow < 0
      ? tr(
          s.targets_deny === 1
            ? 'sensors.localPolicy.sum.targetsAny.one'
            : 'sensors.localPolicy.sum.targetsAny.other',
          undefined,
          { deny: s.targets_deny }
        )
      : tr('sensors.localPolicy.sum.targets', undefined, {
          allow: s.targets_allow,
          deny: s.targets_deny,
        })
  )
  lines.push(tr('sensors.localPolicy.sum.private', undefined, { value: allowed(s.allow_private) }))
  lines.push(
    tr('sensors.localPolicy.sum.ports', undefined, {
      value: s.ports ? s.ports : tr('sensors.localPolicy.sum.any'),
    })
  )
  if (s.tools)
    lines.push(
      tr('sensors.localPolicy.sum.tools', undefined, {
        value: s.tools.length ? s.tools.join(', ') : none,
      })
    )
  if (s.checks)
    lines.push(
      tr('sensors.localPolicy.sum.jobTypes', undefined, {
        value: s.checks.length ? s.checks.join(', ') : none,
      })
    )
  lines.push(
    tr('sensors.localPolicy.sum.templates', undefined, { value: allowed(s.allow_custom_templates) })
  )
  lines.push(
    tr('sensors.localPolicy.sum.interactsh', undefined, { value: allowed(s.allow_interactsh) })
  )
  if (s.max_rps) lines.push(tr('sensors.localPolicy.sum.rate', undefined, { n: s.max_rps }))
  if (s.max_job_seconds)
    lines.push(tr('sensors.localPolicy.sum.jobTime', undefined, { n: s.max_job_seconds }))
  return lines
}

/**
 * The host command that writes a reviewed policy to the sensor's default
 * path (read by the sensor at start and again on SIGHUP). The policy text is
 * the API's rendering; the heredoc delimiter never occurs in it.
 */
export function policyApplyCommand(policy: string): string {
  const body = policy.endsWith('\n') ? policy : `${policy}\n`
  return [
    'sudo install -d -m 0755 /etc/openctem',
    "sudo tee /etc/openctem/sensor-policy.yaml >/dev/null <<'OPENCTEM_POLICY'",
    `${body}OPENCTEM_POLICY`,
    'sudo chmod 0644 /etc/openctem/sensor-policy.yaml',
    '',
  ].join('\n')
}
