import { describe, expect, it } from 'vitest'
import type { ApiFinding } from '../../api/finding-api.types'
import { findingDescription, findingShortName, toFindingDetail } from '../finding-detail'
import { riskSignals } from '../finding-signals'
import { fixGuidance, upgradeCommands } from '../fix-guidance'

/** The live reference finding: cross-spawn ReDoS on demo-web-storefront. */
function crossSpawn(over: Partial<ApiFinding> = {}): ApiFinding {
  return {
    id: 'dcdc3001-0000-0000-0000-000000000006',
    tenant_id: 't',
    asset_id: 'dcdc1111-0000-0000-0000-000000000001',
    asset: {
      id: 'dcdc1111-0000-0000-0000-000000000001',
      name: 'demo-web-storefront',
      type: 'web_application',
      criticality: 'critical',
      exposure: 'public',
      is_internet_accessible: true,
    },
    source: 'sca',
    tool_name: 'npm-audit',
    tool_version: '10.2.4',
    message: 'cross-spawn ReDoS vulnerability',
    description: 'cross-spawn ReDoS vulnerability',
    severity: 'high',
    cvss_score: 7.5,
    cve_id: 'CVE-2024-21538',
    status: 'new',
    is_triaged: false,
    fingerprint: 'fp',
    created_at: '2026-05-10T12:22:38Z',
    updated_at: '2026-05-10T12:22:38Z',
    first_detected_at: '2026-05-07T12:22:38Z',
    last_seen_at: '2026-05-10T12:22:38Z',
    sla_status: 'overdue',
    sla_deadline: '2026-05-12T12:22:38Z',
    priority_class: 'P1',
    priority_class_reason: 'high severity, reachable, no compensating controls',
    is_reachable: true,
    reachable_from_count: 1,
    is_internet_accessible: true,
    is_in_kev: false,
    component: {
      id: 'c',
      name: 'cross-spawn',
      version: '7.0.3',
      ecosystem: 'npm',
      purl: 'pkg:npm/cross-spawn@7.0.3',
      fixed_in: '7.0.5',
      dependency_type: 'transitive',
      manifest_file: 'package.json',
      depth: 2,
    },
    vulnerability: {
      id: 'v',
      cve_id: 'CVE-2024-21538',
      title: 'cross-spawn ReDoS',
      description:
        'Regular expression denial of service in cross-spawn package via crafted argument.',
      cvss_score: 7.5,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      epss_score: 0.00868,
      epss_percentile: 57.276,
      exploit_available: false,
      exploit_maturity: 'none',
      fixed_versions: ['7.0.5', '6.0.6'],
      published_at: '2024-11-08T05:15:00Z',
    },
    ...over,
  } as ApiFinding
}

describe('toFindingDetail', () => {
  it('maps the scanner facts, both vectors and the scanner output (research 24 P0-3)', () => {
    const d = toFindingDetail(
      crossSpawn({
        family: 'General',
        vpr_score: 8.9,
        cvss_version: '3.x',
        cve_ids: ['CVE-2024-21538', 'CVE-2024-0001'],
        patch_published_at: '2024-01-01T00:00:00Z',
        exploit_available: true,
        network_port: 443,
        network_transport: 'tcp',
        network_service: 'https',
        cvss_v2_vector: 'AV:N/AC:L/Au:N/C:P/I:N/A:N',
        cvss_v3_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        scanner_output: {
          text: 'raw <b>output</b>',
          updated_at: '2026-10-01T00:00:00Z',
          truncated: false,
        },
      })
    )
    expect(d.scannerFacts).toMatchObject({
      family: 'General',
      vprScore: 8.9,
      cvssVersion: '3.x',
      cveIds: ['CVE-2024-21538', 'CVE-2024-0001'],
      exploitAvailable: true,
      networkPort: 443,
      cvssV2Vector: 'AV:N/AC:L/Au:N/C:P/I:N/A:N',
    })
    expect(d.scannerOutput).toEqual({
      text: 'raw <b>output</b>',
      updatedAt: '2026-10-01T00:00:00Z',
      truncated: false,
    })
    // The finding's own exploit verdict (the column) raises the exploitation signal.
    expect(riskSignals(d).some((s) => s.key === 'exploit' && s.label === 'Public exploit')).toBe(
      true
    )
    expect(toFindingDetail(crossSpawn()).scannerOutput).toBeUndefined()
  })

  it('maps the CTEM signals the old page dropped', () => {
    const f = toFindingDetail(crossSpawn())
    expect(f.priorityClass).toBe('P1')
    expect(f.priorityClassReason).toMatch(/reachable/)
    expect(f.slaDeadline).toBe('2026-05-12T12:22:38Z')
    expect(f.reachableFromCount).toBe(1)
    expect(f.isInternetAccessible).toBe(true)
    // EPSS is on the CVE record, not on the finding row.
    expect(f.epssScore).toBe(0.00868)
    expect(f.epssPercentile).toBe(57.276)
    expect(f.cvssVector).toMatch(/^CVSS:3.1/)
    expect(f.assets[0]).toMatchObject({
      name: 'demo-web-storefront',
      criticality: 'critical',
      exposure: 'public',
    })
    expect(f.component).toMatchObject({ name: 'cross-spawn', fixedIn: '7.0.5' })
    expect(f.advisory?.fixedVersions).toEqual(['7.0.5', '6.0.6'])
  })

  it('names the page by CVE and package, not by its ID', () => {
    expect(findingShortName(toFindingDetail(crossSpawn()))).toBe('CVE-2024-21538 · cross-spawn')
    expect(
      findingShortName(toFindingDetail(crossSpawn({ cve_id: undefined, vulnerability: undefined })))
    ).toBe('cross-spawn ReDoS vulnerability')
  })

  it('reads the advisory when the scanner repeats the title as the description', () => {
    const d = findingDescription(toFindingDetail(crossSpawn()))
    expect(d.fromAdvisory).toBe(true)
    expect(d.text).toMatch(/^Regular expression denial of service/)
    const own = findingDescription(
      toFindingDetail(crossSpawn({ description: 'A real, scanner-written explanation.' }))
    )
    expect(own).toEqual({ text: 'A real, scanner-written explanation.', fromAdvisory: false })
    // No description, but a message that says more than the title.
    const msg = findingDescription(
      toFindingDetail(
        crossSpawn({
          title: 'Stripe live secret key committed',
          description: undefined,
          message: 'Found a Stripe Access Token.',
          vulnerability: undefined,
        })
      )
    )
    expect(msg).toEqual({ text: 'Found a Stripe Access Token.', fromAdvisory: false })
  })
})

describe('riskSignals', () => {
  it('stacks exploitation, exposure and impact for the reference finding', () => {
    const s = riskSignals(toFindingDetail(crossSpawn()))
    const labels = s.map((x) => x.label)
    expect(labels).toEqual([
      'No known exploit',
      'EPSS 0.87% · 57th percentile',
      'Internet-facing',
      'Reachable from 1 entry point',
      'Critical asset',
    ])
    expect(s.find((x) => x.key === 'exploit')?.effect).toBe('lowers')
    expect(s.find((x) => x.key === 'epss')?.effect).toBe('neutral')
    expect(s.find((x) => x.key === 'internet')?.effect).toBe('raises')
  })

  it('puts KEV first and never claims "no exploit" for a KEV CVE', () => {
    const f = toFindingDetail(
      crossSpawn({
        is_in_kev: true,
        kev_due_date: '2026-01-01',
        vulnerability: {
          ...crossSpawn().vulnerability!,
          exploit_maturity: 'weaponized',
          epss_score: 0.94,
        },
      })
    )
    const s = riskSignals(f)
    expect(s[0]).toMatchObject({ key: 'kev', effect: 'raises' })
    expect(s.find((x) => x.key === 'exploit')?.label).toBe('Weaponized exploit')
    expect(s.find((x) => x.key === 'epss')?.effect).toBe('raises')
  })

  it('says nothing about exploits when there is no advisory', () => {
    const f = toFindingDetail(crossSpawn({ vulnerability: undefined, cve_id: undefined }))
    expect(riskSignals(f).some((x) => x.key === 'exploit')).toBe(false)
  })
})

describe('fixGuidance', () => {
  it('turns the reference finding into an upgrade with an npm override', () => {
    const g = fixGuidance(toFindingDetail(crossSpawn()))
    expect(g).toMatchObject({
      kind: 'upgrade',
      packageName: 'cross-spawn',
      from: '7.0.3',
      to: '7.0.5',
      dependencyType: 'transitive',
      otherFixedVersions: ['6.0.6'],
    })
    if (g?.kind !== 'upgrade') throw new Error('expected an upgrade')
    expect(g.commands[0].code).toContain('"cross-spawn": "^7.0.5"')
  })

  it('installs a direct npm dependency directly', () => {
    expect(upgradeCommands('npm', 'lodash', '4.17.21', 'direct')[0].code).toBe(
      'npm install lodash@^4.17.21'
    )
    expect(upgradeCommands('go', 'golang.org/x/crypto', '0.31.0')[0].code).toBe(
      'go get golang.org/x/crypto@v0.31.0'
    )
    expect(upgradeCommands('pypi', 'django', '4.2.17')[0].code).toBe('pip install "django>=4.2.17"')
    expect(upgradeCommands('unknown-eco', 'x', '1')).toEqual([])
  })

  it('says there is no fix when the advisory lists none', () => {
    const g = fixGuidance(
      toFindingDetail(
        crossSpawn({
          component: { ...crossSpawn().component!, fixed_in: undefined },
          vulnerability: { ...crossSpawn().vulnerability!, fixed_versions: [] },
        })
      )
    )
    expect(g).toEqual({ kind: 'no-fix', packageName: 'cross-spawn', from: '7.0.3' })
  })

  it('asks to revoke and rotate an exposed secret', () => {
    const g = fixGuidance(
      toFindingDetail(
        crossSpawn({
          source: 'secret',
          component: undefined,
          vulnerability: undefined,
          secret_type: 'api_key',
          secret_service: 'Stripe',
          secret_in_history_only: true,
        })
      )
    )
    expect(g?.kind).toBe('rotate-secret')
    if (g?.kind !== 'rotate-secret') throw new Error()
    expect(g.steps[0]).toMatch(/Revoke the exposed Stripe credential/)
    expect(g.steps[2]).toMatch(/history/)
  })

  it('shows expected vs actual for a misconfiguration', () => {
    const g = fixGuidance(
      toFindingDetail(
        crossSpawn({
          source: 'iac',
          component: undefined,
          vulnerability: undefined,
          misconfig_policy_id: 'AVD-AWS-0088',
          misconfig_resource_type: 'aws_s3_bucket',
          misconfig_resource_name: 'logs',
          misconfig_expected: 'server_side_encryption_configuration set',
          misconfig_actual: 'not set',
        })
      )
    )
    expect(g).toMatchObject({
      kind: 'misconfig',
      resource: 'aws_s3_bucket logs',
      expected: 'server_side_encryption_configuration set',
    })
  })

  it('hides the card for scanner boilerplate', () => {
    const g = fixGuidance(
      toFindingDetail(
        crossSpawn({
          source: 'sast',
          component: undefined,
          vulnerability: undefined,
          recommendation: 'No recommendation provided by scanner.',
        })
      )
    )
    expect(g).toBeNull()
  })
})
