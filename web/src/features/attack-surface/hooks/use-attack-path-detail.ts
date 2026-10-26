'use client'

import useSWR from 'swr'
import { useTenant } from '@/context/tenant-provider'
import { get } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'

// GET /api/v1/attack-surface/attack-paths/{id}: the routes from internet-facing
// entry points to one asset (api/docs/architecture/attack-paths.md).

interface PathFindingResponse {
  id: string
  title: string
  cve_id?: string
  severity: string
  epss?: number
  kev: boolean
}

interface PathNodeResponse {
  key: string
  hidden?: boolean
  role: string
  asset_id?: string
  name?: string
  asset_type?: string
  exposure?: string
  criticality?: string
  is_crown_jewel?: boolean
  open_findings: number
  kev_findings: number
  weight?: number
  basis?: string
  finding?: PathFindingResponse
}

interface PathDetailResponse {
  target: string
  nodes: PathNodeResponse[] | null
  edges: { from: string; to: string; relationship?: string; paths: number[] }[] | null
  paths: { nodes: string[]; length: number; likelihood?: number; kev_steps: number }[] | null
  choke_points: { node: string; breaks: number }[] | null
  total_paths: number
  capped: boolean
  computed_at: string
}

export type PathRole = 'entry' | 'hop' | 'target'
export type PathBasis = 'epss' | 'kev' | 'severity' | 'assumed'

export interface PathFinding {
  id: string
  title: string
  cveId: string
  severity: string
  epss: number | null
  kev: boolean
}

export interface PathNode {
  key: string
  /** A step outside the viewer's data scope: nothing but key and role is known. */
  hidden: boolean
  role: PathRole
  assetId: string
  name: string
  assetType: string
  exposure: string
  criticality: string
  isCrownJewel: boolean
  openFindings: number
  kevFindings: number
  /** Likelihood of the step onto this asset; null when hidden. */
  weight: number | null
  basis: PathBasis | null
  finding: PathFinding | null
}

export interface PathEdge {
  /** '' for the step from the internet onto an entry point. */
  from: string
  to: string
  relationship: string
  paths: number[]
}

export interface AttackPath {
  nodes: string[]
  length: number
  /** Product of the step weights; null when a step is hidden. */
  likelihood: number | null
  kevSteps: number
}

export interface AttackPathDetail {
  target: string
  nodes: PathNode[]
  edges: PathEdge[]
  paths: AttackPath[]
  chokePoints: { node: string; breaks: number }[]
  totalPaths: number
  capped: boolean
  computedAt: string
}

const ROLES: PathRole[] = ['entry', 'hop', 'target']
const BASES: PathBasis[] = ['epss', 'kev', 'severity', 'assumed']

export function transformPathDetail(d: PathDetailResponse): AttackPathDetail {
  return {
    target: d.target,
    nodes: (d.nodes ?? []).map((n) => ({
      key: n.key,
      hidden: n.hidden === true,
      role: ROLES.includes(n.role as PathRole) ? (n.role as PathRole) : 'hop',
      assetId: n.asset_id ?? '',
      name: n.name ?? '',
      assetType: n.asset_type ?? '',
      exposure: n.exposure ?? '',
      criticality: n.criticality ?? '',
      isCrownJewel: n.is_crown_jewel === true,
      openFindings: n.open_findings ?? 0,
      kevFindings: n.kev_findings ?? 0,
      weight: typeof n.weight === 'number' ? n.weight : null,
      basis: BASES.includes(n.basis as PathBasis) ? (n.basis as PathBasis) : null,
      finding: n.finding
        ? {
            id: n.finding.id,
            title: n.finding.title,
            cveId: n.finding.cve_id ?? '',
            severity: n.finding.severity,
            epss: typeof n.finding.epss === 'number' ? n.finding.epss : null,
            kev: n.finding.kev,
          }
        : null,
    })),
    edges: (d.edges ?? []).map((e) => ({
      from: e.from,
      to: e.to,
      relationship: e.relationship ?? '',
      paths: e.paths ?? [],
    })),
    paths: (d.paths ?? []).map((p) => ({
      nodes: p.nodes ?? [],
      length: p.length,
      likelihood: typeof p.likelihood === 'number' ? p.likelihood : null,
      kevSteps: p.kev_steps ?? 0,
    })),
    chokePoints: d.choke_points ?? [],
    totalPaths: d.total_paths ?? 0,
    capped: d.capped === true,
    computedAt: d.computed_at,
  }
}

async function fetchPathDetail(url: string): Promise<AttackPathDetail> {
  return transformPathDetail(await get<PathDetailResponse>(url))
}

/** The attack paths to one asset; no request without a target or assets:read. */
export function useAttackPathDetail(assetId: string | null | undefined) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const key =
    currentTenant && can(Permission.AssetsRead) && assetId
      ? `/api/v1/attack-surface/attack-paths/${encodeURIComponent(assetId)}`
      : null
  const { data, error, isLoading, mutate } = useSWR<AttackPathDetail>(key, fetchPathDetail, {
    revalidateOnFocus: false,
    dedupingInterval: 60000,
  })
  return { detail: data, error, isLoading: key ? isLoading : false, mutate }
}
