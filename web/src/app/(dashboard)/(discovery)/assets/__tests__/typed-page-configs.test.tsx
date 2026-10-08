/**
 * Every typed asset page must show what ingest actually stores.
 *
 * The pages used to read keys ingest never writes (`technology`, `server`,
 * flat `port` / `asn` / `cert_*`), so scanned assets showed "-" everywhere
 * and the real data only appeared as raw key/values in the drawer. Each
 * test renders a page's columns and drawer sections against an asset shaped
 * exactly as ingest stores it (see `__fixtures__/ingest-shaped-assets.ts`)
 * and checks the facts appear, then against an empty asset and checks it
 * invents no value: a fact nothing collected is an empty cell (`—`) in the
 * list and one "Not collected yet: …" line in the drawer
 * (ui-style-contract §7, "Unknown facts").
 */
import { describe, expect, it } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import type { Asset } from '@/features/assets'
import type { AssetPageConfig } from '@/features/assets/types/page-config.types'
import {
  bareService,
  ctisCertificate,
  ctisIpWithAsn,
  ctisRootDomain,
  scannedApiWithoutDetails,
  sdkLiveHost,
  sdkOpenPort,
  sensorDnsDomain,
  sensorHttpService,
  sensorHttpServiceNoTech,
  sensorIpWithPorts,
} from '@/features/assets/lib/__fixtures__/ingest-shaped-assets'
import { websitesConfig } from '../websites/config'
import { servicesConfig } from '../services/config'
import { ipAddressesConfig } from '../ip-addresses/config'
import { domainsConfig } from '../domains/config'
import { certificatesConfig } from '../certificates/config'
import { apisConfig } from '../apis/config'
import { databasesConfig } from '../databases/config'
import { serverlessConfig } from '../serverless/config'
import { resolveDetailSections } from '@/features/assets/lib/detail-sections'
import { TypedDetailSections } from '@/features/assets/components/typed-detail-sections'

type CellFn = (ctx: { row: { original: Asset } }) => ReactNode

/** Render every column cell of a config for one asset, one per test id. */
function renderRow(config: AssetPageConfig, asset: Asset) {
  render(
    <div>
      {config.columns.map((col: ColumnDef<Asset>, i) => {
        const id = (col.id ?? (col as { accessorKey?: string }).accessorKey ?? String(i)) as string
        const cell = col.cell as CellFn | undefined
        return (
          <div key={id} data-testid={`col-${id}`}>
            {cell ? cell({ row: { original: asset } }) : null}
          </div>
        )
      })}
    </div>
  )
  return (id: string) => within(screen.getByTestId(`col-${id}`))
}

/** Render every drawer section field of a config for one asset. */
function renderDetail(config: AssetPageConfig, asset: Asset) {
  render(
    <div>
      {(config.detailSections ?? []).flatMap((section) =>
        section.fields.map((f) => (
          <div key={`${section.title}-${f.label}`} data-testid={`field-${f.label}`}>
            {f.getValue(asset)}
          </div>
        ))
      )}
    </div>
  )
  return (label: string) => within(screen.getByTestId(`field-${label}`))
}

/** The drawer's "Not collected yet" facts for one asset. */
const notCollected = (config: AssetPageConfig, asset: Asset) =>
  resolveDetailSections(config.detailSections ?? [], asset).notCollected

/** No cell shows a dashed "unknown" chip or "Unknown" / "Not collected" text. */
function expectNoUnknownText(container: HTMLElement = document.body) {
  expect(container.querySelector('.border-dashed')).toBeNull()
  expect(container.textContent ?? '').not.toMatch(/unknown|not collected|not resolved/i)
}

const csv = (config: AssetPageConfig, asset: Asset) =>
  Object.fromEntries((config.exportFields ?? []).map((f) => [f.header, f.accessor(asset)]))

describe('services page', () => {
  it('shows an httpx service as ingest stores it', () => {
    const col = renderRow(servicesConfig, sensorHttpService)
    expect(col('port').getByText('443')).toBeInTheDocument()
    expect(col('protocol').getByText('HTTPS')).toBeInTheDocument()
    expect(col('version').getByText('nginx/1.25.3')).toBeInTheDocument()
    expect(col('http_status').getByText('200')).toBeInTheDocument()
    expect(col('technology').getByTitle('Nginx 1.25.3')).toBeInTheDocument()
    expect(col('tls').getByText('TLS')).toBeInTheDocument()
  })

  it('shows an sdk-go open port with flat keys, without HTTP-only cells', () => {
    const col = renderRow(servicesConfig, sdkOpenPort)
    expect(col('port').getByText('22')).toBeInTheDocument()
    expect(col('protocol').getByText('TCP')).toBeInTheDocument()
    expect(col('version').getByText('ssh OpenSSH 9.6p1')).toBeInTheDocument()
    expect(col('http_status').queryByText('Status unknown')).toBeNull()
  })

  it('shows an empty cell instead of defaulting to TCP', () => {
    const col = renderRow(servicesConfig, bareService)
    expect(col('port').getByText('—')).toBeInTheDocument()
    expect(col('protocol').getByText('—')).toBeInTheDocument()
    expect(col('protocol').queryByText('TCP')).toBeNull()
    expect(col('tls').getByText('—')).toBeInTheDocument()
    expect(col('version').getByText('—')).toBeInTheDocument()
    expectNoUnknownText()
    expect(servicesConfig.copyAction?.getValue(bareService)).toBe('staging.example.org')
    expect(csv(servicesConfig, bareService).Protocol).toBe('')
  })

  it('drawer names the missing facts once instead of "Unknown" rows', () => {
    expect(notCollected(servicesConfig, bareService)).toEqual([
      'protocol',
      'transport',
      'product',
      'TLS',
      'IP addresses',
      'banner',
    ])
    // HTTP-only facts are not a gap on an SSH port.
    expect(notCollected(servicesConfig, sdkOpenPort)).not.toContain('HTTP status')
    // An HTTPS service without its certificate says so in the same line.
    expect(notCollected(servicesConfig, sensorHttpService)).toContain('TLS certificate')
  })

  it('drawer reads banner, title and technologies', () => {
    const field = renderDetail(servicesConfig, sensorHttpService)
    expect(field('Title').getByText('Example Shop | Home')).toBeInTheDocument()
    expect(field('Technologies').getByTitle('jQuery 3.3.1')).toBeInTheDocument()
    expect(csv(servicesConfig, sensorHttpService).Technologies).toBe(
      'Nginx 1.25.3;React;jQuery 3.3.1'
    )
  })
})

describe('websites page', () => {
  it('reads status, title, technologies and TLS from the ingest keys', () => {
    const col = renderRow(websitesConfig, sdkLiveHost)
    expect(col('http_status').getByText('301')).toBeInTheDocument()
    expect(col('http_status').getByText('301 Moved Permanently')).toBeInTheDocument()
    expect(col('technology').getByTitle('Cloudflare')).toBeInTheDocument()
    expect(col('ssl').getByText('TLS')).toBeInTheDocument()
  })

  it('drawer shows web server, CDN, IP and a safe redirect link', () => {
    const field = renderDetail(websitesConfig, sdkLiveHost)
    expect(field('Web server').getByText('cloudflare')).toBeInTheDocument()
    expect(field('CDN').getByText('cloudflare')).toBeInTheDocument()
    expect(field('IP addresses').getByText('203.0.113.24')).toBeInTheDocument()
    const link = field('Redirects to').getByRole('link')
    expect(link).toHaveAttribute('href', 'https://www.example.net/en/')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer nofollow')
  })

  it('keeps known negatives, hides unknowns and has no default 200', () => {
    const col = renderRow(websitesConfig, sensorHttpServiceNoTech)
    expect(col('technology').getByText('No technologies detected')).toBeInTheDocument()
    expect(col('ssl').getByText('No TLS')).toBeInTheDocument()
    cleanup()
    const bare = renderRow(websitesConfig, bareService)
    expect(bare('http_status').getByText('—')).toBeInTheDocument()
    expect(bare('technology').getByText('—')).toBeInTheDocument()
    expect(bare('ssl').getByText('—')).toBeInTheDocument()
    expect(screen.queryByText('200')).toBeNull()
    expectNoUnknownText()
    expect(csv(websitesConfig, bareService)['HTTP Status']).toBe('')
  })
})

describe('IP addresses page', () => {
  it('reads ASN and ports from ip_address.*', () => {
    const col = renderRow(ipAddressesConfig, ctisIpWithAsn)
    expect(col('asnOrg').getByText('AS64502')).toBeInTheDocument()
    expect(col('asnOrg').getByText('Example Transit')).toBeInTheDocument()
    expect(col('open_ports').getByText('8443/tcp')).toBeInTheDocument()
  })

  it('reads naabu ports and leaves an uncollected ASN empty', () => {
    const col = renderRow(ipAddressesConfig, sensorIpWithPorts)
    expect(col('open_ports').getByText('22/tcp')).toBeInTheDocument()
    expect(col('open_ports').getByText('+1')).toBeInTheDocument()
    expect(col('asnOrg').getByText('—')).toBeInTheDocument()
    expectNoUnknownText()
    expect(notCollected(ipAddressesConfig, sensorIpWithPorts)).toEqual(['ASN', 'organization'])
    expect(csv(ipAddressesConfig, sensorIpWithPorts)['Open Ports']).toBe(
      '22/tcp;80/tcp;443/tcp;8443/tcp'
    )
  })
})

describe('domains page', () => {
  it('reads CNAME and A records from domain.dns_records', () => {
    const col = renderRow(domainsConfig, sensorDnsDomain)
    expect(col('dnsInfo').getByText('www.pages.example-host.net')).toBeInTheDocument()
    expect(col('dnsInfo').getByText('203.0.113.24')).toBeInTheDocument()
    expect(col('dnsInfo').getByText('+1')).toBeInTheDocument()
  })

  it('reads registration from domain.*', () => {
    const field = renderDetail(domainsConfig, ctisRootDomain)
    expect(field('Registrar').getByText('Example Registrar, Inc.')).toBeInTheDocument()
    expect(field('Nameservers').getByText('ns2.example.com')).toBeInTheDocument()
    expect(csv(domainsConfig, ctisRootDomain)['Expiry Date']).toBe('2027-05-14')
  })

  it('leaves the DNS cell empty when there is no DNS data', () => {
    const sub = { ...bareService, type: 'subdomain' } as Asset
    const col = renderRow(domainsConfig, sub)
    expect(col('dnsInfo').getByText('—')).toBeInTheDocument()
    expectNoUnknownText()
    // Registration is not a gap on a subdomain.
    expect(notCollected(domainsConfig, sub)).toEqual(['DNS records', 'resolved IPs'])
    expect(notCollected(domainsConfig, { ...bareService, type: 'domain' } as Asset)).toEqual([
      'registrar',
      'expiry date',
      'DNS records',
      'resolved IPs',
      'nameservers',
    ])
  })
})

describe('certificates page', () => {
  it('reads certificate.* (issuer, expiry, SANs, key, wildcard)', () => {
    const cert = ctisCertificate(new Date(Date.now() + 40 * 24 * 3600 * 1000).toISOString())
    const col = renderRow(certificatesConfig, cert)
    expect(col('issuer').getByText("Let's Encrypt")).toBeInTheDocument()
    expect(col('certStatus').getByText(/Valid · 4\d days left/)).toBeInTheDocument()
    expect(col('sans').getByText('*.example.com')).toBeInTheDocument()
    const field = renderDetail(certificatesConfig, cert)
    expect(field('Subject').getByText('*.example.com')).toBeInTheDocument()
    expect(field('Key').getByText('RSA 2048 bits')).toBeInTheDocument()
    expect(field('Wildcard').getByText('Yes')).toBeInTheDocument()
    expect(field('Self-signed').getByText('No')).toBeInTheDocument()
  })

  it('never shows an unknown certificate as valid', () => {
    const bare = { ...bareService, type: 'certificate' } as Asset
    const col = renderRow(certificatesConfig, bare)
    expect(col('certStatus').getByText('—')).toBeInTheDocument()
    expect(col('issuer').getByText('—')).toBeInTheDocument()
    expect(screen.queryByText(/valid/i)).toBeNull()
    expectNoUnknownText()
    cleanup()
    const field = renderDetail(certificatesConfig, bare)
    expect(field('Wildcard').queryByText(/yes|no/i)).toBeNull()
    expect(notCollected(certificatesConfig, bare)).toEqual([
      'expiry',
      'issuer',
      'subject',
      'valid from',
      'valid until',
      'algorithm',
      'key',
      'serial number',
      'wildcard',
      'self-signed',
      'fingerprint',
      'SANs',
    ])
  })
})

describe('APIs page', () => {
  it('does not claim "No Auth", REST or 0 endpoints for an API nobody described', () => {
    const col = renderRow(apisConfig, scannedApiWithoutDetails)
    expect(col('metadata.auth_type').getByText('—')).toBeInTheDocument()
    expect(col('metadata.auth_type').queryByText('No Auth')).toBeNull()
    expect(col('metadata.api_type').getByText('—')).toBeInTheDocument()
    expect(col('metadata.endpoint_count').getByText('—')).toBeInTheDocument()
    expect(col('http_status').getByText('—')).toBeInTheDocument()
    expect(col('tls').getByText('—')).toBeInTheDocument()
    expectNoUnknownText()
    expect(notCollected(apisConfig, scannedApiWithoutDetails)).toEqual([
      'authentication',
      'HTTP status',
      'TLS',
    ])
    const row = csv(apisConfig, scannedApiWithoutDetails)
    expect(row['Auth Type']).toBe('')
    expect(row.Type).toBe('')
    expect(row.Endpoints).toBe('')
  })
})

describe('databases and serverless pages', () => {
  it('leave an unrecorded engine or provider empty, without a dashed chip', () => {
    const db = { ...bareService, type: 'database' } as Asset
    const fn = { ...bareService, type: 'host', subType: 'serverless' } as Asset
    const dbCol = renderRow(databasesConfig, db)
    expect(dbCol('metadata.engine').getByText('—')).toBeInTheDocument()
    cleanup()
    const fnCol = renderRow(serverlessConfig, fn)
    expect(fnCol('metadata.cloud_provider').getByText('—')).toBeInTheDocument()
    expect(document.body.querySelector('.border-dashed')).toBeNull()
  })
})

describe('typed drawer sections', () => {
  it('end with one "Not collected yet" line naming exactly the missing facts', () => {
    const partial = {
      ...bareService,
      subType: 'http',
      name: 'https://partial.example.org',
      metadata: { status_code: 200, port: 443, protocol: 'https' },
    } as Asset
    const { container } = render(
      <TypedDetailSections sections={servicesConfig.detailSections ?? []} asset={partial} />
    )
    const notes = container.querySelectorAll('[data-slot="not-collected"]')
    expect(notes).toHaveLength(1)
    expect(notes[0]).toHaveTextContent(
      'Not collected yet: transport, product, TLS certificate, IP addresses, banner, page title, technologies'
    )
    // The note is the last thing in the facts.
    expect(container.lastElementChild?.lastElementChild).toBe(notes[0])
    // The known facts stay, and no row says "Unknown".
    expect(screen.getByText('HTTPS')).toBeInTheDocument()
    expect(screen.getByText('200')).toBeInTheDocument()
    expect(container.textContent).not.toMatch(/unknown/i)
  })

  it('omit the line when nothing is missing', () => {
    const { container } = render(
      <TypedDetailSections
        sections={ipAddressesConfig.detailSections ?? []}
        asset={ctisIpWithAsn}
      />
    )
    expect(container.querySelector('[data-slot="not-collected"]')).toBeNull()
    expect(screen.getByText('AS64502')).toBeInTheDocument()
  })

  it('still say what is missing when no field has a value', () => {
    const { container } = render(
      <TypedDetailSections
        sections={apisConfig.detailSections ?? []}
        asset={scannedApiWithoutDetails}
      />
    )
    expect(container.querySelectorAll('[data-slot="not-collected"]')).toHaveLength(1)
    expect(container).toHaveTextContent('Not collected yet: authentication, HTTP status, TLS')
  })
})
