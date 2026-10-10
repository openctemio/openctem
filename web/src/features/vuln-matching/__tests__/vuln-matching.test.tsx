/**
 * Inventory vulnerability matching in the console (RFC-066): the asset
 * Software tab, the "Why this finding" panel and the policy form.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

import { AssetSoftwareTab, severityCounts } from '../components/asset-software-tab'
import { VersionMatchPanel } from '../components/version-match-panel'
import {
  VulnMatchingSettingsForm,
  toVulnMatchingPayload,
} from '../components/vuln-matching-settings-form'
import { reasonLabel, sourceLabel, validateVulnMatching, versionMatchEvidence } from '../types'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

beforeEach(() => {
  api.get.mockReset()
  api.put.mockReset()
  toast.success.mockReset()
  toast.error.mockReset()
})

const nginx = {
  id: 's1',
  product: 'nginx',
  vendor: 'F5',
  cpe: 'f5:nginx',
  known: true,
  version: '1.18.0',
  qualifier: 'ubuntu',
  location: 'tcp/443',
  source: 'service',
  evidence: 'nginx/1.18.0 (Ubuntu)',
  confidence: 35,
  first_seen_at: '2026-10-01T00:00:00Z',
  last_seen_at: '2026-10-09T00:00:00Z',
  stale: false,
  matches: [
    {
      cve_id: 'CVE-2021-23017',
      severity: 'high',
      in_kev: false,
      epss: 0.2,
      confidence: 35,
      label: 'potential',
      range: '>= 0.6.18, < 1.20.1',
      reasons: ['edition_unverified'],
      all_versions: false,
      in_policy: false,
    },
    {
      cve_id: 'CVE-2099-0001',
      severity: 'critical',
      in_kev: true,
      epss: 0,
      confidence: 85,
      label: 'likely',
      range: '< 2.0',
      reasons: [],
      all_versions: false,
      in_policy: true,
    },
  ],
}

describe('AssetSoftwareTab', () => {
  it('lists software and expands its CVEs with labels, policy and a findings link', async () => {
    api.get.mockResolvedValue({
      data: [
        nginx,
        {
          id: 's2',
          product: 'acme portal',
          version: '',
          known: false,
          source: 'technology',
          confidence: 50,
          matches: [],
        },
      ],
    })
    wrap(<AssetSoftwareTab assetId="a1" />)

    expect(await screen.findByText('nginx')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/v1/assets/a1/software')
    expect(screen.getByText('ubuntu')).toBeInTheDocument()
    expect(screen.getByText('Unrecognised')).toBeInTheDocument()
    expect(screen.getByText('version unknown')).toBeInTheDocument()
    expect(screen.getByText('No CVEs')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /nginx/ }))
    const link = screen.getByRole('link', { name: 'CVE-2021-23017' })
    expect(link).toHaveAttribute('href', '/findings?cve_id=CVE-2021-23017&asset_id=a1')
    expect(screen.getByText('Below policy')).toBeInTheDocument()
    expect(screen.getByText('Finding')).toBeInTheDocument()
    expect(screen.getByText(/Potential · 35/)).toBeInTheDocument()
    expect(screen.getByText(/Likely · 85/)).toBeInTheDocument()
    expect(screen.getByText('KEV')).toBeInTheDocument()
    expect(screen.getByText(reasonLabel('edition_unverified'))).toBeInTheDocument()
  })

  it('explains where software comes from when there is none', async () => {
    api.get.mockResolvedValue({ data: [] })
    wrap(<AssetSoftwareTab assetId="a1" />)
    expect(await screen.findByText('No software seen yet')).toBeInTheDocument()
    expect(screen.getByText(/HTTP technology detection/)).toBeInTheDocument()
  })

  it('says it could not load instead of showing an empty list', async () => {
    api.get.mockRejectedValue(Object.assign(new Error('not found'), { statusCode: 404 }))
    wrap(<AssetSoftwareTab assetId="a1" />)
    expect(await screen.findByText(/the software list/)).toBeInTheDocument()
    expect(screen.queryByText('No software seen yet')).not.toBeInTheDocument()
  })

  it('counts CVEs by severity, highest first', () => {
    expect(severityCounts(nginx.matches)).toEqual([
      { severity: 'critical', count: 1 },
      { severity: 'high', count: 1 },
    ])
    expect(severityCounts(undefined)).toEqual([])
  })
})

describe('VersionMatchPanel', () => {
  const metadata = {
    version_match: {
      label: 'potential',
      confidence: 35,
      product: 'OpenSSH',
      vendor: 'OpenBSD',
      version: '8.2p1',
      qualifier: 'ubuntu-4ubuntu0.5',
      location: 'tcp/22',
      evidence: 'OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
      range: '< 9.3p2',
      reasons: ['all_versions', 'platform_condition_unverified'],
      source: 'nvd',
    },
  }

  it('shows why the finding exists', () => {
    render(<VersionMatchPanel metadata={metadata} />)
    expect(screen.getByText('Why this finding')).toBeInTheDocument()
    expect(screen.getByText('OpenBSD OpenSSH 8.2p1')).toBeInTheDocument()
    expect(screen.getByText('< 9.3p2')).toBeInTheDocument()
    expect(screen.getByText(/Potential · confidence 35/)).toBeInTheDocument()
    expect(screen.getByText('ubuntu-4ubuntu0.5')).toBeInTheDocument()
    expect(screen.getByText(reasonLabel('platform_condition_unverified'))).toBeInTheDocument()
    expect(screen.getByText('Source: NVD')).toBeInTheDocument()
  })

  it('renders nothing without evidence', () => {
    const { container } = render(<VersionMatchPanel metadata={{ other: 1 }} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('reads only well-typed evidence fields', () => {
    expect(versionMatchEvidence({ version_match: 'x' })).toBeUndefined()
    expect(versionMatchEvidence({ version_match: [] })).toBeUndefined()
    const ev = versionMatchEvidence({
      version_match: { confidence: '9', reasons: ['a', 1], product: 2 },
    })
    expect(ev?.confidence).toBeUndefined()
    expect(ev?.reasons).toEqual(['a'])
    expect(ev?.product).toBeUndefined()
  })
})

describe('labels', () => {
  it('turns reason and source codes into words', () => {
    expect(reasonLabel('all_versions')).toMatch(/every version/)
    expect(reasonLabel('unknown_code')).toBe('unknown code')
    expect(sourceLabel('technology')).toBe('Technology detection')
    expect(sourceLabel('other')).toBe('other')
  })
})

describe('VulnMatchingSettingsForm', () => {
  it('validates confidence and muted products', () => {
    expect(validateVulnMatching({ min_confidence: 50 })).toBeNull()
    expect(validateVulnMatching({ min_confidence: null })).toBeNull()
    expect(validateVulnMatching({ min_confidence: 101 })).toMatch(/0 and 100/)
    expect(validateVulnMatching({ min_confidence: 1.5 })).toMatch(/whole number/)
    expect(validateVulnMatching({ muted_products: [' '] })).toMatch(/1 to 200/)
    expect(
      validateVulnMatching({ muted_products: Array.from({ length: 101 }, (_, i) => `p${i}`) })
    ).toMatch(/At most 100/)
  })

  it('sends defaults as zero values', () => {
    expect(
      toVulnMatchingPayload({
        enabled: true,
        min_confidence: '',
        min_severity: 'high',
        include_distro_builds: false,
        internet_facing_only: true,
        muted_products: [' OpenSSH ', ''],
      })
    ).toEqual({
      enabled: true,
      min_confidence: 0,
      min_severity: '',
      include_distro_builds: false,
      internet_facing_only: true,
      muted_products: ['OpenSSH'],
    })
  })

  it('saves with the section ETag and refuses an invalid confidence', async () => {
    api.put.mockResolvedValue({ enabled: true, min_confidence: 70 })
    const onSaved = vi.fn()
    wrap(
      <>
        <VulnMatchingSettingsForm
          initial={{ enabled: false }}
          etag={'"e1"'}
          onSaved={onSaved}
          formId="f"
        />
        <button type="submit" form="f">
          Save
        </button>
      </>
    )
    const conf = screen.getByLabelText('Minimum confidence')
    await userEvent.type(conf, '250')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(toast.error).toHaveBeenCalledWith(expect.stringMatching(/0 and 100/))
    expect(api.put).not.toHaveBeenCalled()

    await userEvent.clear(conf)
    await userEvent.type(conf, '70')
    await userEvent.click(screen.getByLabelText('Create findings from version matches'))
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(api.put).toHaveBeenCalled())
    const [url, body, opts] = api.put.mock.calls[0]
    expect(url).toBe('/api/v1/organization/settings/vuln-matching')
    expect(body).toMatchObject({ enabled: true, min_confidence: 70 })
    expect(opts).toEqual({ headers: { 'If-Match': '"e1"' } })
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
  })

  it('reports a concurrent change and re-reads', async () => {
    api.put.mockRejectedValue({ code: 'SETTINGS_CONFLICT' })
    const onSaved = vi.fn()
    wrap(
      <>
        <VulnMatchingSettingsForm initial={{ enabled: true }} onSaved={onSaved} formId="f" />
        <button type="submit" form="f">
          Save
        </button>
      </>
    )
    await userEvent.click(screen.getByLabelText('Internet-facing assets only'))
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(expect.stringMatching(/Someone else changed/))
    )
    expect(onSaved).toHaveBeenCalled()
  })

  it('shows the NVD attribution', () => {
    wrap(<VulnMatchingSettingsForm initial={{}} formId="f" />)
    expect(screen.getByText(/not endorsed or certified by the NVD/)).toBeInTheDocument()
  })
})
