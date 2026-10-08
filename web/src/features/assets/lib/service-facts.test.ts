import { describe, expect, it } from 'vitest'
import type { Asset } from '../types'
import {
  asnInfo,
  cnames,
  dnsRecordTypes,
  domainExpiry,
  httpStatusCode,
  ipAddresses,
  nameservers,
  openPorts,
  pageTitle,
  parseTechnology,
  redirectChain,
  redirectTarget,
  registrar,
  serviceName,
  servicePort,
  serviceProtocol,
  serviceTransport,
  serviceVersion,
  technologies,
  tlsFacts,
  webServer,
} from './service-facts'
import {
  bareService,
  ctisCertificate,
  ctisIpWithAsn,
  ctisRootDomain,
  sdkLiveHost,
  sdkOpenPort,
  sensorDnsDomain,
  sensorHttpService,
  sensorHttpServiceNoTech,
  sensorIpWithPorts,
} from './__fixtures__/ingest-shaped-assets'

const NOW = Date.parse('2026-10-01T00:00:00Z')
const DAY = 24 * 60 * 60 * 1000

function withMeta(metadata: Record<string, unknown>, extra: Partial<Asset> = {}): Asset {
  return { ...bareService, ...extra, metadata } as Asset
}

describe('HTTP facts', () => {
  it('reads the status ingest stores, and never defaults one', () => {
    expect(httpStatusCode(sensorHttpService)).toBe(200)
    expect(httpStatusCode(sdkLiveHost)).toBe(301)
    expect(httpStatusCode(withMeta({ status_code: '404' }))).toBe(404)
    expect(httpStatusCode(bareService)).toBeNull()
    // httpx never reports 0; a 0 is "not recorded".
    expect(httpStatusCode(withMeta({ status_code: 0 }))).toBeNull()
  })

  it('reads the redirect chain without repeating the final status', () => {
    expect(
      redirectChain(withMeta({ status_code: 200, chain_status_codes: [301, 302, 200] }))
    ).toEqual([301, 302])
    expect(redirectChain(sensorHttpService)).toEqual([])
    expect(redirectTarget(sdkLiveHost)).toBe('https://www.example.net/en/')
  })

  it('reads title and web server from both producers', () => {
    expect(pageTitle(sensorHttpService)).toBe('Example Shop | Home')
    expect(pageTitle(sensorHttpServiceNoTech)).toBeUndefined()
    // The sensor puts the web server in service.name; sdk-go sends web_server,
    // which every write path folds into `server`.
    expect(webServer(sensorHttpService)).toBe('nginx/1.25.3')
    expect(webServer(sdkLiveHost)).toBe('cloudflare')
    expect(webServer(withMeta({ server: 'Apache' }))).toBe('Apache')
    // service.name of an SSH service is not a web server.
    expect(webServer(withMeta({ service: 'ssh', protocol: 'ssh', port: 22 }))).toBeUndefined()
  })
})

describe('technologies', () => {
  it('parses httpx "Name:version" strings', () => {
    expect(parseTechnology('jQuery:3.3.1')).toEqual({ name: 'jQuery', version: '3.3.1' })
    expect(parseTechnology('React')).toEqual({ name: 'React' })
    expect(parseTechnology('HTTP/3')).toEqual({ name: 'HTTP/3' })
    // A colon not followed by a version stays in the name.
    expect(parseTechnology('Foo:Bar')).toEqual({ name: 'Foo:Bar' })
  })

  it('reads the schema key `technologies` (writes fold the singular into it)', () => {
    expect(technologies(sensorHttpService)).toEqual([
      { name: 'Nginx', version: '1.25.3' },
      { name: 'React' },
      { name: 'jQuery', version: '3.3.1' },
    ])
    expect(technologies(withMeta({ technologies: ['React', 'Node.js'] }))).toEqual([
      { name: 'React' },
      { name: 'Node.js' },
    ])
    // A synonym is folded on write, never read.
    expect(technologies(withMeta({ technology: 'React' }))).toBeNull()
  })

  it('tells "probed, none found" from "never fingerprinted"', () => {
    // The sensor writes technologies: null when httpx found none.
    expect(technologies(sensorHttpServiceNoTech)).toEqual([])
    expect(technologies(bareService)).toBeNull()
  })
})

describe('service facts', () => {
  it('reads the nested service map ingest writes', () => {
    expect(servicePort(sensorHttpService)).toBe(443)
    expect(serviceProtocol(sensorHttpService)).toBe('https')
    expect(serviceTransport(sensorHttpService)).toBeUndefined()
  })

  it('reads the flat open-port keys', () => {
    expect(servicePort(sdkOpenPort)).toBe(22)
    expect(serviceProtocol(sdkOpenPort)).toBe('tcp')
    expect(serviceTransport(sdkOpenPort)).toBe('tcp')
    expect(serviceVersion(sdkOpenPort)).toBe('OpenSSH 9.6p1')
    expect(serviceName(sdkOpenPort)).toBe('ssh')
  })

  it('does not assume TCP or a port', () => {
    expect(servicePort(bareService)).toBeNull()
    expect(serviceProtocol(bareService)).toBeUndefined()
    expect(serviceTransport(bareService)).toBeUndefined()
  })
})

describe('network facts', () => {
  it('collects IPs from httpx, DNS records and the flat keys', () => {
    expect(ipAddresses(sdkLiveHost)).toEqual(['203.0.113.24'])
    expect(ipAddresses(sensorDnsDomain)).toEqual(['203.0.113.24', '203.0.113.25'])
    expect(ipAddresses(withMeta({ resolved_ips: '192.0.2.1, 192.0.2.2' }))).toEqual([
      '192.0.2.1',
      '192.0.2.2',
    ])
    // ingest stores a MAP under ip_address on IP assets: never an IP string.
    expect(ipAddresses(ctisIpWithAsn)).toEqual([])
    expect(ipAddresses(withMeta({ ip_address: '198.51.100.9' }))).toEqual(['198.51.100.9'])
  })

  it('reads CNAMEs from DNS records and the flat key', () => {
    expect(cnames(sensorDnsDomain)).toEqual(['www.pages.example-host.net'])
    expect(cnames(withMeta({ cname_target: 'x.example-cdn.net' }))).toEqual(['x.example-cdn.net'])
    expect(dnsRecordTypes(sensorDnsDomain)).toEqual(['CNAME', 'A'])
  })

  it('reads ASN from ip_address (number) and the flat keys (string)', () => {
    expect(asnInfo(ctisIpWithAsn)).toEqual({ asn: 'AS64502', org: 'Example Transit' })
    expect(asnInfo(withMeta({ asn: 'AS64500', asn_org: 'Example' }))).toEqual({
      asn: 'AS64500',
      org: 'Example',
    })
    expect(asnInfo(sensorIpWithPorts)).toEqual({ asn: undefined, org: undefined })
  })

  it('reads open ports, and tells "none open" from "not scanned"', () => {
    expect(openPorts(sensorIpWithPorts)?.map((p) => p.port)).toEqual([22, 80, 443, 8443])
    // A port is a service of its own, never a host property.
    expect(openPorts(withMeta({ open_ports: ['443/tcp'] }))).toBeNull()
    expect(openPorts(withMeta({ ports: [] }))).toEqual([])
    expect(openPorts(bareService)).toBeNull()
  })

  it('reads domain registration from the nested map', () => {
    expect(registrar(ctisRootDomain)).toBe('Example Registrar, Inc.')
    expect(domainExpiry(ctisRootDomain)?.toISOString()).toBe('2027-05-14T00:00:00.000Z')
    expect(nameservers(ctisRootDomain)).toEqual(['ns1.example.com', 'ns2.example.com'])
    expect(registrar(bareService)).toBeUndefined()
  })
})

describe('tlsFacts', () => {
  it('reads a certificate asset', () => {
    const t = tlsFacts(ctisCertificate(new Date(NOW + 10 * DAY).toISOString()), NOW)
    expect(t.kind).toBe('cert')
    if (t.kind !== 'cert') return
    expect(t.cert.status).toBe('expiring')
    expect(t.cert.daysLeft).toBe(10)
    expect(t.cert.issuer).toBe("Let's Encrypt")
    expect(t.cert.sans).toEqual(['*.example.com', 'example.com'])
  })

  it('says TLS without a certificate when only the scheme is known', () => {
    expect(tlsFacts(sensorHttpService, NOW)).toEqual({ kind: 'tls' })
  })

  it('reads plain HTTP as "No TLS", from the scheme the probe used', () => {
    expect(tlsFacts(sensorHttpServiceNoTech, NOW)).toEqual({ kind: 'none' })
  })

  it('reads TLS only when it was measured (ingest stores `has_tls` only when on)', () => {
    expect(tlsFacts(withMeta({ port: 8443 }), NOW)).toEqual({ kind: 'not_collected' })
    expect(tlsFacts(withMeta({ port: 8443, has_tls: true }), NOW)).toEqual({ kind: 'tls' })
  })

  it('keeps a certificate without expiry "unknown", never valid', () => {
    const facts = tlsFacts(withMeta({ issuer_org: 'Example CA' }), NOW)
    expect(facts.kind).toBe('cert')
    if (facts.kind === 'cert') expect(facts.cert.status).toBe('unknown')
  })

  it('is "not collected" when nothing was recorded, whatever the name says', () => {
    expect(tlsFacts(bareService, NOW)).toEqual({ kind: 'not_collected' })
    expect(
      tlsFacts(withMeta({}, { name: 'https://typed-in.example.com' } as Partial<Asset>), NOW)
    ).toEqual({ kind: 'not_collected' })
  })
})
