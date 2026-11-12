/**
 * The design's one sample dataset, typed. Every design board draws from the
 * same data (organization "Example Corp", the people below, today 11 Nov 2026,
 * the findings table), so the real page reproduces a board only when it is fed
 * exactly these values. Add a value here when a page in the manifest needs it,
 * copied from the design's dataset, never from live data.
 *
 * Only reserved names: example.com / example.org domains, the documentation
 * address ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24, and made-up
 * people. No secrets: a credential-shaped value would be a fixture bug.
 */

/** The fixed "now" of every board: Wednesday 11 Nov 2026, morning. */
export const TODAY = '2026-11-11T09:00:00Z'

export const ORGANIZATION = {
  name: 'Example Corp',
  slug: 'example-corp',
  others: ['Example Corp staging', 'Example Corp lab'],
} as const

export interface Person {
  name: string
  email: string
  role: string
}

export const PEOPLE = {
  signedIn: { name: 'Linh Tran', email: 'linh.tran@example.com', role: 'Security lead' },
  apiTeam: { name: 'Minh Pham', email: 'minh.pham@example.com', role: 'API team' },
  networkTeam: { name: 'Sam Rivera', email: 'sam.rivera@example.com', role: 'Network team' },
  approver: { name: 'Alex Kim', email: 'alex.kim@example.com', role: 'Approver' },
} as const satisfies Record<string, Person>

export const PROGRAM = {
  openFindings: 418,
  actionableP0P1: 27,
  knownExploited: 7,
  withinSlaPercent: 87,
  overdue: 3,
  dueThisWeek: 9,
  assets: 1284,
  inbox: 12,
  sensors: 7,
} as const

export interface SampleFinding {
  id: string
  title: string
  asset: string
  priority: 'P0' | 'P1' | 'P2' | 'P3'
  status: 'New' | 'Confirmed' | 'In progress'
  owner: string
}

/** The findings table of the dataset (same id, asset, priority and status on every board). */
export const FINDINGS: readonly SampleFinding[] = [
  {
    id: 'CVE-2023-4966',
    title: 'Citrix ADC session token leak',
    asset: 'vpn.example.com',
    priority: 'P0',
    status: 'Confirmed',
    owner: 'Sam Rivera',
  },
  {
    id: 'CVE-2024-6387',
    title: 'OpenSSH signal handler race allows remote code execution',
    asset: 'ssh.example.com',
    priority: 'P0',
    status: 'Confirmed',
    owner: 'Platform team',
  },
  {
    id: 'CVE-2021-44228',
    title: 'Log4j remote code execution in the API gateway',
    asset: 'api.example.com',
    priority: 'P1',
    status: 'In progress',
    owner: 'Minh Pham',
  },
  {
    id: 'F-20418',
    title: 'Git metadata folder is readable',
    asset: 'dev.example.com',
    priority: 'P1',
    status: 'New',
    owner: 'Unassigned',
  },
]

/**
 * The long-data variant: the longest values the layout pass feeds a page
 * (names that do not fit, counts with many digits). Vietnamese text is longer
 * than English, so the pass also switches the locale.
 */
export const LONG = {
  organizationName:
    'Example Corporation International Holdings, Southeast Asia Regional Security Operations',
  providerName:
    'Example Corporation International Holdings single sign-on (production tenant, primary region)',
  count: 1_284_093,
} as const
