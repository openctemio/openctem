import type { AttackPathDetail, PathNode } from '../../hooks/use-attack-path-detail'

export const node = (
  key: string,
  role: PathNode['role'],
  extra: Partial<PathNode> = {}
): PathNode => ({
  key,
  hidden: false,
  role,
  assetId: `asset-${key}`,
  name: key,
  assetType: 'host',
  exposure: role === 'entry' ? 'public' : 'private',
  criticality: 'high',
  isCrownJewel: role === 'target',
  openFindings: 3,
  kevFindings: 0,
  weight: 0.5,
  basis: 'severity',
  finding: {
    id: `f-${key}`,
    title: `${key} finding`,
    cveId: '',
    severity: 'critical',
    epss: null,
    kev: false,
  },
  ...extra,
})

/** The mockup: vpn reaches billing-db through jump or through ci. */
export function mockupDetail(): AttackPathDetail {
  return {
    target: 'n0',
    nodes: [
      node('n0', 'target', { name: 'billing-db', weight: 0.4 }),
      node('n1', 'entry', {
        name: 'vpn-gw-hq',
        weight: 0.9,
        basis: 'kev',
        kevFindings: 1,
        finding: {
          id: 'f-vpn',
          title: 'VPN RCE',
          cveId: 'CVE-2026-30112',
          severity: 'critical',
          epss: 0.88,
          kev: true,
        },
      }),
      node('n2', 'hop', { name: 'jump-host-02', weight: 0.6 }),
      node('n3', 'hop', { name: 'ci-runner-3', weight: 0.3 }),
    ],
    edges: [
      { from: '', to: 'n1', relationship: '', paths: [0, 1] },
      { from: 'n1', to: 'n2', relationship: 'has_access_to', paths: [0] },
      { from: 'n2', to: 'n0', relationship: 'authenticates_to', paths: [0] },
      { from: 'n1', to: 'n3', relationship: 'has_access_to', paths: [1] },
      { from: 'n3', to: 'n0', relationship: 'has_access_to', paths: [1] },
    ],
    paths: [
      { nodes: ['n1', 'n2', 'n0'], length: 2, likelihood: 0.216, kevSteps: 1 },
      { nodes: ['n1', 'n3', 'n0'], length: 2, likelihood: 0.108, kevSteps: 1 },
    ],
    chokePoints: [
      { node: 'n1', breaks: 2 },
      { node: 'n2', breaks: 1 },
      { node: 'n3', breaks: 1 },
    ],
    totalPaths: 2,
    capped: false,
    computedAt: '2026-10-25T10:30:00Z',
  }
}
