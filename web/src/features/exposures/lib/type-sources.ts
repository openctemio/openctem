import type { FindingSource } from '@/lib/api/finding-types'

/**
 * The finding sources each Exposures type page owns. Together they partition
 * every API finding source: code, secrets and misconfigurations take their own
 * sources and vulnerabilities takes all the rest (network and host scans,
 * containers, external attack surface, manual testing, imports).
 */
export const CODE_SOURCES: FindingSource[] = ['sast']
export const SECRET_SOURCES: FindingSource[] = ['secret']
export const MISCONFIG_SOURCES: FindingSource[] = ['iac', 'cspm']

const NOT_VULNERABILITY: ReadonlySet<FindingSource> = new Set([
  ...CODE_SOURCES,
  ...SECRET_SOURCES,
  ...MISCONFIG_SOURCES,
])

export const ALL_FINDING_SOURCES: FindingSource[] = [
  'sast',
  'dast',
  'sca',
  'secret',
  'iac',
  'container',
  'cspm',
  'easm',
  'va',
  'rasp',
  'waf',
  'siem',
  'manual',
  'pentest',
  'bug_bounty',
  'red_team',
  'external',
  'threat_intel',
  'vendor',
  'sarif',
  'sca_tool',
]

export const VULNERABILITY_SOURCES: FindingSource[] = ALL_FINDING_SOURCES.filter(
  (s) => !NOT_VULNERABILITY.has(s)
)
