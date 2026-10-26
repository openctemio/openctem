import type { Vulnerability } from '../types'
import type { CveExposure, CveExposureAssetsResponse } from '../types/exposure'

/** The page's answer for the example CVE in the design (example data only). */
export function exposureFixture(over: Partial<CveExposure> = {}): CveExposure {
  return {
    cve_id: 'CVE-2026-41187',
    in_catalog: true,
    verdict: 'confirmed',
    findings: {
      total: 27,
      active: 19,
      by_status: {
        new: 12,
        confirmed: 7,
        resolved: 4,
        accepted: 2,
        false_positive: 1,
        duplicate: 1,
      },
      by_priority: { P0: 5, P1: 9, P2: 5, P3: 0, none: 0 },
      worst_priority: 'P0',
      in_task: 8,
      not_in_task: 11,
    },
    assets: { impacted: 14, crown_jewels: 2, internet_facing: 5, with_findings: 15 },
    possible: { assets: 3, products: ['proxy-core'] },
    not_affected: { assets: 1, products: ['proxy-core'] },
    components: [
      {
        product_id: 'p1',
        name: 'proxy-core',
        purl: 'pkg:apk/proxy-core@2.4.1',
        version: '2.4.1',
        fixed_versions: ['2.4.7'],
        recommended_fix: '2.4.7',
        assets: 11,
        active_findings: 15,
      },
      {
        product_id: 'p1',
        name: 'proxy-core',
        purl: 'pkg:apk/proxy-core@2.3.9',
        version: '2.3.9',
        fixed_versions: ['2.4.7'],
        recommended_fix: '2.4.7',
        assets: 3,
        active_findings: 4,
      },
    ],
    upgrades: [
      {
        product_id: 'p1',
        name: 'proxy-core',
        target: '2.4.7',
        major_change: false,
        fixes_findings: 19,
        on_assets: 14,
        no_fix_findings: 0,
      },
    ],
    sources: [
      { name: 'edge-zone-1 sensor', source: 'easm', assets: 12 },
      { name: 'Dependency scanning', source: 'sca', assets: 6 },
    ],
    single_source_assets: 2,
    timeline: {
      first_seen_at: '2026-10-03T08:00:00Z',
      last_seen_at: '2026-10-25T06:00:00Z',
      last_fixed_at: '2026-10-20T09:00:00Z',
      fixed: 4,
      reopened: 1,
      last_reopened_at: '2026-10-22T09:00:00Z',
    },
    intel: {
      aliases: [{ id: 'GHSA-x2f7-q9m4-7c3p', source: 'ghsa', synced_at: '2026-10-03T00:00:00Z' }],
      cwes: ['CWE-94'],
      feeds: [
        { source: 'epss', status: 'success', last_sync_at: new Date().toISOString() },
        { source: 'kev', status: 'success', last_sync_at: new Date().toISOString() },
      ],
      emerging: { id: 'a1', state: 'new', level: 'immediate', tier: 'confirmed' },
    },
    ...over,
  }
}

export function catalogFixture(over: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: 'v1',
    cve_id: 'CVE-2026-41187',
    title: 'Remote code execution in proxy-core debug handler',
    description:
      'An unauthenticated request to the debug evaluation route runs code as the proxy user.',
    severity: 'critical',
    cvss_score: 9.3,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    epss_score: 0.94,
    epss_percentile: 99.6,
    cisa_kev: {
      date_added: '2026-10-14',
      due_date: '2026-11-04',
      ransomware_use: 'Known',
      is_past_due: false,
    },
    exploit_available: true,
    exploit_maturity: 'weaponized',
    references: [{ type: 'advisory', url: 'https://example.com/advisory/proxy-core' }],
    fixed_versions: ['2.4.7'],
    published_at: '2026-10-01T00:00:00Z',
    modified_at: '2026-10-20T00:00:00Z',
    status: 'open',
    risk_score: 90,
    ...over,
  } as Vulnerability
}

export function assetsFixture(): CveExposureAssetsResponse {
  return {
    data: [
      {
        asset_id: 'a-1',
        name: 'billing-gw',
        asset_type: 'host',
        criticality: 'critical',
        crown_jewel: true,
        internet_facing: true,
        owner: 'Payments',
        open_findings: 3,
        total_findings: 3,
        worst_priority: 'P0',
        worst_severity: 'critical',
      },
      {
        asset_id: 'a-2',
        name: 'lab-proxy-9',
        asset_type: 'host',
        criticality: 'low',
        crown_jewel: false,
        internet_facing: false,
        owner: '',
        open_findings: 0,
        total_findings: 1,
        worst_priority: '',
        worst_severity: '',
      },
    ],
    total: 2,
    page: 1,
    per_page: 10,
    total_pages: 1,
  }
}
