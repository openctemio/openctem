/**
 * The findings practice switch (docs: api/docs/architecture/finding-practices.md).
 * A finding's practice is the program that triages it. The list opens on
 * "Vulnerabilities" (every practice except compliance, so failed benchmark
 * checks never mix with exploitable weaknesses); one click shows compliance,
 * a single practice, or everything. The choice is the `practice` URL param
 * (absent = vulnerabilities, `all` = no condition), so it is linkable and a
 * saved view keeps it.
 */

export type FindingPractice =
  | 'aspm'
  | 'infra'
  | 'external'
  | 'cloud'
  | 'compliance'
  | 'offensive'
  | 'identity'
  | 'runtime'
  | 'other'

/** The practices in display order. */
export const FINDING_PRACTICES: FindingPractice[] = [
  'aspm',
  'infra',
  'external',
  'cloud',
  'compliance',
  'offensive',
  'identity',
  'runtime',
  'other',
]

/** What the switch shows: the two main slices, one practice, or all. */
export type PracticeView = 'vulnerabilities' | 'all' | FindingPractice

export const DEFAULT_PRACTICE_VIEW: PracticeView = 'vulnerabilities'

/** The URL param the switch owns. */
export const PRACTICE_PARAM = 'practice'

/**
 * English fallbacks of `findings.practice.<value>.label` and `.description`.
 */
export const PRACTICE_VIEW_TEXT: Record<PracticeView, { label: string; description: string }> = {
  vulnerabilities: {
    label: 'Vulnerabilities',
    description: 'Every finding except compliance checks',
  },
  compliance: {
    label: 'Compliance',
    description: 'Benchmark check results (CIS, STIG, vendor hardening)',
  },
  aspm: { label: 'Application security', description: 'Code, dependencies, images and CI builds' },
  infra: { label: 'Infrastructure', description: 'Network and host vulnerability assessment' },
  external: {
    label: 'External exposure',
    description: 'What the internet sees of the organization',
  },
  cloud: { label: 'Cloud posture', description: 'Cloud configuration findings' },
  offensive: { label: 'Pentest and bug bounty', description: 'Findings from manual testing' },
  identity: { label: 'Identity', description: 'Findings on identities and accounts' },
  runtime: { label: 'Runtime', description: 'Runtime detections' },
  other: { label: 'Other', description: 'Findings with no signal for a practice' },
  all: { label: 'All', description: 'Every finding' },
}

export const practiceLabelKey = (v: PracticeView) => `findings.practice.${v}.label`
export const practiceDescriptionKey = (v: PracticeView) => `findings.practice.${v}.description`

function isPractice(v: string): v is FindingPractice {
  return (FINDING_PRACTICES as string[]).includes(v)
}

/** The view a URL value names; the default for anything else. */
export function parsePracticeView(raw: string | null | undefined): PracticeView {
  const v = (raw ?? '').trim().toLowerCase()
  if (v === 'all' || v === 'vulnerabilities') return v
  return isPractice(v) ? v : DEFAULT_PRACTICE_VIEW
}

/** The list query params of a view (the API's practice filter). */
export function practiceViewParams(view: PracticeView): Record<string, string> {
  if (view === 'all') return {}
  if (view === 'vulnerabilities') return { practice_not: 'compliance' }
  return { practice: view }
}

/**
 * The tabs to show: Vulnerabilities and Compliance always, then each other
 * practice that holds findings (or is the one chosen), then All.
 */
export function practiceTabs(
  counts: Partial<Record<FindingPractice, number>> | undefined,
  current: PracticeView
): PracticeView[] {
  const out: PracticeView[] = ['vulnerabilities', 'compliance']
  for (const p of FINDING_PRACTICES) {
    if (p === 'compliance') continue
    if ((counts?.[p] ?? 0) > 0 || p === current) out.push(p)
  }
  out.push('all')
  return out
}
