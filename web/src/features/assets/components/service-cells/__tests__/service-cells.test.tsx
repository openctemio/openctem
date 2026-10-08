import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { Asset } from '../../../types'
import { tlsFacts, type TlsFacts } from '../../../lib/service-facts'
import {
  bareService,
  ctisCertificate,
  sensorHttpService,
  sensorHttpServiceNoTech,
  sensorIpWithPorts,
} from '../../../lib/__fixtures__/ingest-shaped-assets'
import {
  EmptyCell,
  HttpStatusChip,
  IssuesChip,
  LabelChips,
  NotCollectedNote,
  OpenPortChips,
  OverflowChips,
  SurfaceFacts,
  SurfaceFactsDetail,
  TechChips,
  TlsSummary,
  cellsForType,
  hasSurfaceFacts,
  httpStatusTone,
  labelError,
  missingSurfaceFacts,
  tlsNotCollected,
  MAX_TAGS_PER_ASSET,
} from '..'

/** No chip in the old dashed "unknown" style, and none of its wording. */
function expectNoUnknownChips(container: HTMLElement) {
  expect(container.querySelector('[data-tone="unknown"]')).toBeNull()
  expect(container.querySelector('.border-dashed')).toBeNull()
  expect(container.textContent ?? '').not.toMatch(/unknown|not collected|not resolved/i)
}
import { FINDINGS_OPEN_STATUSES } from '@/features/findings/lib/list-defaults'

describe('HttpStatusChip', () => {
  it('colours by the class of the final status', () => {
    expect(httpStatusTone(200)).toBe('success')
    expect(httpStatusTone(302)).toBe('info')
    expect(httpStatusTone(401)).toBe('warning')
    expect(httpStatusTone(403)).toBe('warning')
    expect(httpStatusTone(404)).toBe('destructive')
    expect(httpStatusTone(503)).toBe('destructive')
  })

  it('shows the redirect chain then the final status', () => {
    render(<HttpStatusChip status={200} chain={[301]} />)
    expect(screen.getByText('301, 200')).toBeInTheDocument()
    expect(screen.getByText('OK')).toBeInTheDocument()
    expect(screen.getByTitle('Redirect chain: 301 → 200')).toHaveAttribute('data-tone', 'success')
  })

  it('renders nothing for a status nobody recorded, never a default 200', () => {
    const { container, rerender } = render(<HttpStatusChip status={null} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<HttpStatusChip status={null} fallback={<EmptyCell />} />)
    expect(screen.getByText('—')).toHaveAttribute('title', 'Not collected')
    expect(screen.queryByText('200')).toBeNull()
  })
})

describe('IssuesChip', () => {
  it("links to the asset's open findings, within the API's 10-status cap", () => {
    render(<IssuesChip assetId="a/1" count={4} />)
    const link = screen.getByRole('link', { name: /4 issues found/ })
    const href = new URL(link.getAttribute('href') ?? '', 'http://x')
    expect(href.pathname).toBe('/findings')
    expect(href.searchParams.get('asset_id')).toBe('a/1')
    const statuses = href.searchParams.get('status')?.split(',') ?? []
    expect(statuses).toEqual([...FINDINGS_OPEN_STATUSES])
    expect(statuses.length).toBeLessThanOrEqual(10)
    expect(statuses).not.toContain('resolved')
  })

  it('renders nothing at zero', () => {
    const { container } = render(<IssuesChip assetId="a" count={0} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('OverflowChips', () => {
  it('shows the first value and "+N" naming the rest', () => {
    render(<OverflowChips label="IP" values={['192.0.2.1', '192.0.2.2', '192.0.2.3']} />)
    expect(screen.getByText('192.0.2.1')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: '2 more IP: 192.0.2.2, 192.0.2.3' })
    ).toHaveTextContent('+2')
  })

  it('renders nothing for no values', () => {
    const { container } = render(<OverflowChips label="CNAME" values={[]} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('TechChips', () => {
  it('shows name and version', () => {
    render(<TechChips technologies={[{ name: 'jQuery', version: '3.3.1' }, { name: 'React' }]} />)
    expect(screen.getByTitle('jQuery 3.3.1')).toBeInTheDocument()
    expect(screen.getByTitle('React')).toBeInTheDocument()
  })

  it('shows "none detected" (data) and hides "never fingerprinted" (unknown)', () => {
    const { container, rerender } = render(<TechChips technologies={[]} />)
    expect(screen.getByText('No technologies detected')).toHaveAttribute('data-tone', 'muted')
    rerender(<TechChips technologies={null} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('TlsSummary', () => {
  const NOW = Date.now()
  const DAY = 24 * 60 * 60 * 1000

  it('shows expiry, issuer and SAN of a certificate', () => {
    const asset = ctisCertificate(new Date(NOW - 133 * DAY).toISOString())
    render(<TlsSummary facts={tlsFacts(asset, NOW)} />)
    expect(screen.getByText('Expired 133 days ago')).toHaveAttribute('data-tone', 'destructive')
    expect(screen.getByText("Let's Encrypt")).toBeInTheDocument()
    expect(screen.getByText('*.example.com')).toBeInTheDocument()
  })

  it('says "Expires in N days" inside the window and "Valid" after', () => {
    const { rerender } = render(
      <TlsSummary facts={tlsFacts(ctisCertificate(new Date(NOW + 18 * DAY).toISOString()), NOW)} />
    )
    expect(screen.getByText('Expires in 18 days')).toHaveAttribute('data-tone', 'warning')
    rerender(
      <TlsSummary facts={tlsFacts(ctisCertificate(new Date(NOW + 212 * DAY).toISOString()), NOW)} />
    )
    expect(screen.getByText('Valid · 212 days left')).toHaveAttribute('data-tone', 'success')
  })

  it('keeps "No TLS" and "TLS" visible and hides "not collected"', () => {
    const { container, rerender } = render(<TlsSummary facts={{ kind: 'none' }} />)
    expect(screen.getByText('No TLS')).toBeInTheDocument()
    rerender(<TlsSummary facts={{ kind: 'tls' }} />)
    expect(
      screen.getByTitle('Served over TLS; the certificate was not collected')
    ).toBeInTheDocument()
    rerender(<TlsSummary facts={{ kind: 'not_collected' }} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('names what is missing about TLS for the drawer line', () => {
    expect(tlsNotCollected({ kind: 'not_collected' })).toBe('TLS')
    expect(tlsNotCollected({ kind: 'tls' })).toBe('TLS certificate')
    expect(tlsNotCollected({ kind: 'none' })).toBeNull()
    expect(
      tlsNotCollected(tlsFacts(ctisCertificate(new Date(NOW + 9 * DAY).toISOString()), NOW))
    ).toBeNull()
  })

  it('shows a certificate without expiry as TLS, never as valid', () => {
    const facts: TlsFacts = {
      kind: 'cert',
      cert: { notAfter: null, daysLeft: null, status: 'unknown', issuer: 'R11', sans: [] },
    }
    render(<TlsSummary facts={facts} />)
    expect(
      screen.getByTitle('The certificate was recorded without an expiry date')
    ).toHaveTextContent('TLS')
    expect(screen.queryByText(/valid/i)).toBeNull()
    expect(tlsNotCollected(facts)).toBe('certificate expiry')
  })
})

describe('LabelChips', () => {
  it('shows labels with "+N" and no add button without write access', () => {
    render(<LabelChips labels={['prod', 'online-store', 'pci']} />)
    expect(screen.getByText('prod')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '1 more labels: pci' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /add label/i })).toBeNull()
  })

  it('adds a label through the popover', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    render(<LabelChips labels={['prod']} onSave={onSave} />)
    fireEvent.click(screen.getByRole('button', { name: /add label/i }))
    fireEvent.change(await screen.findByLabelText('Add label'), {
      target: { value: '  marketing-site ' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(['prod', 'marketing-site']))
  })

  it('refuses a duplicate, an over-long label and a 51st label', () => {
    expect(labelError(['prod'], 'prod')).toMatch(/already/)
    expect(labelError([], 'x'.repeat(51))).toMatch(/at most 50 characters/)
    const full = Array.from({ length: MAX_TAGS_PER_ASSET }, (_, i) => `t${i}`)
    expect(labelError(full, 'one-more')).toMatch(/at most 50 labels/)
    expect(labelError([], ' ')).toBe('Enter a label')
    expect(labelError(full.slice(1), 'ok')).toBeNull()
  })
})

describe('scanner text is text', () => {
  it('renders HTML from a scanner as literal text', () => {
    const evil = '<img src=x onerror="alert(1)">'
    const { container } = render(
      <>
        <TechChips technologies={[{ name: evil }]} />
        <OverflowChips label="CNAME" values={[evil]} />
        <LabelChips labels={[evil]} />
      </>
    )
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getAllByText(evil).length).toBeGreaterThan(0)
  })
})

describe('cellsForType', () => {
  it('gives service cells to the external-surface types only', () => {
    for (const [type, sub] of [
      ['service', 'http'],
      ['service', 'open_port'],
      ['service', 'discovered_url'],
      ['service', undefined],
      ['application', 'website'],
      ['application', 'web_application'],
      ['application', 'api'],
      ['domain', undefined],
      ['subdomain', undefined],
      ['ip_address', undefined],
      ['certificate', undefined],
      ['website', undefined],
      ['http_service', undefined],
      ['open_port', undefined],
      ['discovered_url', undefined],
      ['api', undefined],
    ] as const) {
      expect(cellsForType(type, sub), `${type}:${sub}`).not.toBeNull()
    }
    for (const type of [
      'repository',
      'cloud_account',
      'kubernetes',
      'identity',
      'database',
      'host',
      'storage',
    ]) {
      expect(cellsForType(type), type).toBeNull()
    }
    expect(cellsForType('application')).toBeNull()
  })

  it('SurfaceFacts renders an http service and nothing for a repository', () => {
    const { container, rerender } = render(<SurfaceFacts asset={sensorHttpService} />)
    expect(screen.getByText('200')).toBeInTheDocument()
    expect(screen.getByTitle('Nginx 1.25.3')).toBeInTheDocument()
    expect(screen.getByText('443/https')).toBeInTheDocument()
    rerender(<SurfaceFacts asset={{ ...bareService, type: 'repository' } as Asset} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('SurfaceFacts renders one muted dash for a DNS name without records', () => {
    const { container } = render(
      <SurfaceFacts asset={{ ...bareService, type: 'subdomain' } as Asset} />
    )
    expect(container).toHaveTextContent(/^—$/)
    expectNoUnknownChips(container)
  })

  it('SurfaceFacts renders an all-unknown row as one "—" and no dashed chips', () => {
    const { container } = render(<SurfaceFacts asset={bareService} />)
    expect(container.textContent).toBe('—')
    expect(screen.getByText('—')).toHaveClass('text-muted-foreground')
    expect(container.querySelector('[data-slot="fact-chip"]')).toBeNull()
    expectNoUnknownChips(container)
    expect(hasSurfaceFacts(bareService)).toBe(false)
  })

  it('SurfaceFacts shows only the known facts of a partly scanned service', () => {
    const partial = {
      ...bareService,
      subType: 'http',
      metadata: { service: { port: 80, protocol: 'http' } },
    } as Asset
    const { container } = render(<SurfaceFacts asset={partial} />)
    expect(screen.getByText('80/http')).toBeInTheDocument()
    expect(screen.getByText('No TLS')).toBeInTheDocument()
    expect(container.textContent).not.toContain('—')
    expectNoUnknownChips(container)
  })

  it('SurfaceFacts keeps the known negatives', () => {
    const { container, rerender } = render(<SurfaceFacts asset={sensorHttpServiceNoTech} />)
    expect(screen.getByText('No technologies detected')).toBeInTheDocument()
    expect(screen.getByText('No TLS')).toBeInTheDocument()
    expect(screen.getByText('403')).toBeInTheDocument()
    expectNoUnknownChips(container)
    const ipNoPorts = {
      ...sensorIpWithPorts,
      metadata: { ip_address: { ports: [] } },
    } as Asset
    rerender(<SurfaceFacts asset={ipNoPorts} />)
    expect(screen.getByText('No open ports')).toBeInTheDocument()
  })

  it('SurfaceFacts shows open ports for an IP', () => {
    render(<SurfaceFacts asset={sensorIpWithPorts} />)
    expect(screen.getByText('22/tcp')).toBeInTheDocument()
  })

  it('OpenPortChips hides "not scanned" and shows "none open"', () => {
    const { container, rerender } = render(<OpenPortChips asset={bareService} />)
    expect(container).toBeEmptyDOMElement()
    rerender(
      <OpenPortChips asset={{ ...bareService, metadata: { ip_address: { ports: [] } } } as Asset} />
    )
    expect(screen.getByText('No open ports')).toBeInTheDocument()
  })
})

describe('drawer: Not collected yet', () => {
  it('lists exactly the missing facts, in cell order, in one line', () => {
    const partial = {
      ...bareService,
      subType: 'http',
      metadata: { service: { port: 443, protocol: 'https' } },
    } as Asset
    expect(missingSurfaceFacts(partial)).toEqual(['HTTP status', 'technologies', 'TLS certificate'])
    const { container } = render(<SurfaceFactsDetail asset={partial} />)
    const notes = container.querySelectorAll('[data-slot="not-collected"]')
    expect(notes).toHaveLength(1)
    expect(notes[0]).toHaveTextContent(
      'Not collected yet: HTTP status, technologies, TLS certificate'
    )
    expect(screen.getByText('443/https')).toBeInTheDocument()
    expect(container.querySelector('[data-tone="unknown"]')).toBeNull()
  })

  it('names every fact for a bare service, with no dash', () => {
    expect(missingSurfaceFacts(bareService)).toEqual(['port', 'HTTP status', 'technologies', 'TLS'])
    const { container } = render(<SurfaceFactsDetail asset={bareService} />)
    expect(container).toHaveTextContent('Not collected yet: port, HTTP status, technologies, TLS')
    expect(container.textContent).not.toContain('—')
  })

  it('is omitted when nothing is missing', () => {
    const complete = {
      ...sensorHttpServiceNoTech,
      metadata: { ...sensorHttpServiceNoTech.metadata, service: { port: 8080, protocol: 'http' } },
    } as Asset
    expect(missingSurfaceFacts(complete)).toEqual([])
    const { container } = render(<SurfaceFactsDetail asset={complete} />)
    expect(container.querySelector('[data-slot="not-collected"]')).toBeNull()
    const { container: empty } = render(<NotCollectedNote items={[]} />)
    expect(empty).toBeEmptyDOMElement()
  })
})
