import { afterEach, describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { AffectedAssets } from '../components/affected-assets'
import type { EmergingThreatAssetGroup } from '../types'
import { host, service } from './fixtures'

function setWidth(width: number) {
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: width })
}

/** Two confirmed hosts (one with two services), one likely, one possible. */
const groups: EmergingThreatAssetGroup[] = [
  {
    tier: 'confirmed',
    hosts: [
      host(
        '192.0.2.20',
        [
          service('http', {
            asset_id: 's-http',
            asset_name: 'http://192.0.2.20',
            internet_facing: false,
            version_seen: '1.24',
            finding_id: 'f-http',
            finding_status: 'new',
          }),
          service('https', {
            asset_id: 's-https',
            asset_name: 'https://192.0.2.20',
            version_seen: '1.25',
            finding_id: 'f-https',
            finding_status: 'confirmed',
            task_id: 't-https',
          }),
        ],
        { criticality: 'critical' }
      ),
      host('web-01', [service('', { asset_id: 'h1', asset_name: 'web-01', asset_type: 'host' })], {
        asset_id: 'h1',
      }),
    ],
  },
  {
    tier: 'likely',
    hosts: [
      host('example.com.vn', [
        service('https:8443', { asset_id: 's-vn', asset_name: 'https://example.com.vn:8443' }),
      ]),
    ],
  },
  {
    tier: 'possible',
    hosts: [
      host('example.org', [
        service('https', {
          asset_id: 's-org',
          asset_name: 'https://example.org',
          version_seen: '',
        }),
      ]),
    ],
  },
]

const hrefs = (el: HTMLElement) =>
  within(el)
    .queryAllByRole('link')
    .map((a) => `${a.textContent} ${a.getAttribute('href')}`)

describe('AffectedAssets', () => {
  const originalWidth = window.innerWidth
  afterEach(() => setWidth(originalWidth))

  it('shows three groups in order, each counting its hosts', () => {
    setWidth(1440)
    render(<AffectedAssets groups={groups} />)
    const headers = screen.getAllByRole('rowgroup').flatMap((g) => {
      const id = g.getAttribute('aria-labelledby')
      const text = id ? document.getElementById(id)?.textContent : null
      return text ? [text.replace(/\s+/g, ' ').trim()] : []
    })
    expect(headers).toEqual([
      'Confirmed affected (2)',
      'Likely affected (1)',
      'Possibly affected (version unknown) (1)',
    ])
    // The tier is said once, by the group: no row repeats it.
    expect(screen.getAllByText('Likely affected')).toHaveLength(1)
    expect(screen.queryByText('No host is confirmed affected.')).toBeNull()
  })

  it('folds the services of a host into one row and links each to its own asset, finding and task', () => {
    setWidth(1440)
    render(<AffectedAssets groups={groups} />)
    const row = screen.getByText('192.0.2.20').closest('tr') as HTMLElement
    // The host is not an asset of its own here: the services are the links.
    expect(hrefs(within(row).getByRole('list', { name: 'Services of 192.0.2.20' }))).toEqual([
      'http /assets/s-http',
      'https /assets/s-https',
    ])
    expect(hrefs(row)).toEqual([
      'http /assets/s-http',
      'https /assets/s-https',
      'New /findings/f-http',
      'Confirmed /findings/f-https',
      'Open task /remediation/tasks/t-https',
    ])
    expect(within(row).getByText('Internet-facing')).toBeInTheDocument()
    expect(within(row).getByText('Critical')).toBeInTheDocument()
    expect(within(row).getByText('1.24, 1.25')).toBeInTheDocument()

    // A non-default port stays in the service's label.
    const vn = screen.getByText('example.com.vn').closest('tr') as HTMLElement
    expect(hrefs(vn)).toEqual(['https:8443 /assets/s-vn'])

    // An asset that is not named by a URL keeps its own row and link.
    const plain = screen.getByRole('link', { name: 'web-01' })
    expect(plain).toHaveAttribute('href', '/assets/h1')
    expect(within(plain.closest('tr') as HTMLElement).getByText('host')).toBeInTheDocument()
  })

  it('says so when no asset is confirmed or likely, and still lists the possible ones', () => {
    setWidth(1440)
    render(<AffectedAssets groups={groups.filter((g) => g.tier === 'possible')} />)
    expect(screen.getByText('No host is confirmed affected.')).toBeInTheDocument()
    expect(screen.getByText('example.org')).toBeInTheDocument()
    expect(screen.queryByText('Confirmed affected')).toBeNull()
  })

  it('a likely match alone is not announced as confirmed', () => {
    setWidth(1440)
    render(<AffectedAssets groups={groups.filter((g) => g.tier === 'likely')} />)
    expect(screen.queryByText('Confirmed affected')).toBeNull()
    expect(screen.queryByText('No host is confirmed affected.')).toBeNull()
    expect(screen.getByText('Likely affected')).toBeInTheDocument()
  })

  it('has only the empty text when the alert has no asset in view', () => {
    const { container } = render(<AffectedAssets groups={[]} />)
    expect(screen.getByText('No host is confirmed affected.')).toBeInTheDocument()
    expect(container.querySelector('table')).toBeNull()
  })

  it('phone: cards under the same group headers, every link kept, the table hidden', () => {
    setWidth(390)
    const { container } = render(<AffectedAssets groups={groups} />)
    expect(container.querySelector('table')?.closest('.hidden')).not.toBeNull()
    expect(
      [...container.querySelectorAll('[data-slot="row-group-header"]')]
        .filter((h) => !h.closest('table'))
        .map((h) => h.textContent?.replace(/\s+/g, ' ').trim())
    ).toEqual([
      'Confirmed affected (2)',
      'Likely affected (1)',
      'Possibly affected (version unknown) (1)',
    ])
    const cardLinks = [...container.querySelectorAll('a')]
      .filter((a) => !a.closest('table'))
      .map((a) => `${a.textContent} ${a.getAttribute('href')}`)
    expect(cardLinks).toEqual([
      'http /assets/s-http',
      'https /assets/s-https',
      'New /findings/f-http',
      'Confirmed /findings/f-https',
      'Open task /remediation/tasks/t-https',
      'web-01 /assets/h1',
      'https:8443 /assets/s-vn',
      'https /assets/s-org',
    ])
  })
})
