/**
 * Assets shaped exactly as ingest stores them, for tests of the asset pages.
 *
 * Each `properties` map below is what the API returns after a sensor report
 * goes through `api/internal/app/ingest`:
 *
 *  - top-level keys are the CTIS `properties` the sensor sent (reserved
 *    discovery keys are stripped by `buildPropertiesFromCTIS`);
 *  - `service`, `ip_address`, `domain`, `certificate` are the nested maps
 *    `mappers.go` builds from CTIS `technical.*` (`buildServiceProperties`
 *    always writes `tls`, even when the sensor never measured it);
 *  - http_service / open_port / discovered_url arrive as type `service` with
 *    sub_type `http` / `open_port` / `discovered_url` (`asset.TypeAliases`).
 *
 * Sources: the sensor's recon parsers (the sensor repository, `internal/executor/recon.go`:
 * httpx, naabu, dnsx, subfinder) and sdk-go's recon converter
 * (`pkg/ctis/recon_converter.go`), which also sends `web_server`, `ip`,
 * `cdn`, `content_length` and `response_time_ms`. All names and addresses
 * are documentation ranges (example.com, 192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24, AS64496-AS64511).
 */

import type { Asset } from '../../types'

const T = '2026-10-01T08:00:00Z'

function base(over: Partial<Asset> & Pick<Asset, 'id' | 'name' | 'type'>): Asset {
  return {
    criticality: 'medium',
    status: 'active',
    scope: 'external',
    exposure: 'public',
    riskScore: 0,
    findingCount: 0,
    metadata: {},
    tags: [],
    firstSeen: T,
    lastSeen: T,
    createdAt: T,
    updatedAt: T,
    ...over,
  } as Asset
}

/** Sensor httpx line → http_service → stored as service / http. */
export const sensorHttpService = base({
  id: 'svc-http-1',
  name: 'https://shop.example.com',
  type: 'service',
  subType: 'http',
  findingCount: 4,
  tags: ['prod', 'online-store'],
  metadata: {
    status_code: 200,
    title: 'Example Shop | Home',
    content_type: 'text/html; charset=utf-8',
    technologies: ['Nginx:1.25.3', 'React', 'jQuery:3.3.1'],
    service: { name: 'nginx/1.25.3', port: 443, protocol: 'https', tls: false },
  },
})

/** Sensor httpx line where httpx fingerprinted nothing: `tech` omitted → null. */
export const sensorHttpServiceNoTech = base({
  id: 'svc-http-2',
  name: 'http://legacy.example.com:8080',
  type: 'service',
  subType: 'http',
  metadata: {
    status_code: 403,
    title: '',
    content_type: 'text/html',
    technologies: null,
    service: { name: '', port: 8080, protocol: 'http', tls: false },
  },
})

/** sdk-go LiveHost (status 2xx/3xx → type service), with redirect and IP. */
export const sdkLiveHost = base({
  id: 'svc-http-3',
  name: 'www.example.net',
  type: 'service',
  metadata: {
    status_code: 301,
    content_length: 162,
    title: '301 Moved Permanently',
    server: 'cloudflare',
    content_type: 'text/html',
    response_time_ms: 87,
    technologies: ['Cloudflare', 'HTTP/3'],
    cdn: 'cloudflare',
    tls_version: 'tls13',
    ip: '203.0.113.24',
    redirect_url: 'https://www.example.net/en/',
    service: { name: 'cloudflare', port: 443, protocol: 'https', tls: true },
  },
})

/** sdk-go open port (one asset per port) → service / open_port, flat keys. */
export const sdkOpenPort = base({
  id: 'svc-port-1',
  name: '198.51.100.7:22/tcp',
  type: 'service',
  subType: 'open_port',
  metadata: {
    host: '198.51.100.7',
    port: 22,
    protocol: 'tcp',
    service: 'ssh',
    version: 'OpenSSH 9.6p1',
    banner: 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13',
  },
})

/** Sensor naabu → ip_address with `ip_address.ports[]`. */
export const sensorIpWithPorts = base({
  id: 'ip-1',
  name: '203.0.113.10',
  type: 'ip_address',
  metadata: {
    ip_address: {
      ports: [
        { port: 443, protocol: 'tcp', state: 'open' },
        { port: 80, protocol: 'tcp', state: 'open' },
        { port: 8443, protocol: 'tcp', state: 'open' },
        { port: 22, protocol: 'tcp', state: 'open' },
      ],
    },
  },
})

/** A CTIS ip_address with ASN data (`ip_address.asn` is a number). */
export const ctisIpWithAsn = base({
  id: 'ip-2',
  name: '192.0.2.40',
  type: 'ip_address',
  metadata: {
    ip_address: {
      version: 4,
      hostname: 'api.example.org',
      asn: 64502,
      asn_org: 'Example Transit',
      country: 'NL',
      ports: [{ port: 8443, protocol: 'tcp', state: 'open', service: 'https' }],
    },
  },
})

/** Sensor dnsx → domain with `domain.dns_records[]`. */
export const sensorDnsDomain = base({
  id: 'dom-1',
  name: 'www.example.com',
  type: 'domain',
  metadata: {
    domain: {
      dns_records: [
        { type: 'CNAME', name: 'www.example.com', value: 'www.pages.example-host.net', ttl: 0 },
        { type: 'A', name: 'www.example.com', value: '203.0.113.24', ttl: 0 },
        { type: 'A', name: 'www.example.com', value: '203.0.113.25', ttl: 0 },
      ],
    },
  },
})

/** CTIS domain with registration data. */
export const ctisRootDomain = base({
  id: 'dom-2',
  name: 'example.com',
  type: 'domain',
  metadata: {
    domain: {
      registrar: 'Example Registrar, Inc.',
      registered_at: '2001-05-14T00:00:00Z',
      expires_at: '2027-05-14T00:00:00Z',
      nameservers: ['ns1.example.com', 'ns2.example.com'],
      dns_records: [{ type: 'NS', name: 'example.com', value: 'ns1.example.com', ttl: 3600 }],
    },
  },
})

/** Sensor subfinder → subdomain, only the passive source. */
export const sensorSubdomain = base({
  id: 'dom-3',
  name: 'dev.example.com',
  type: 'subdomain',
  metadata: { source: 'crtsh' },
})

/** CTIS certificate → `certificate.*` (CT monitor and scanners). */
export function ctisCertificate(notAfter: string): Asset {
  return base({
    id: 'cert-1',
    name: '*.example.com',
    type: 'certificate',
    metadata: {
      certificate: {
        serial_number: '04:3a:9f:00:11',
        subject_cn: '*.example.com',
        sans: ['*.example.com', 'example.com'],
        issuer_cn: 'R11',
        issuer_org: "Let's Encrypt",
        not_before: '2026-08-01T00:00:00Z',
        not_after: notAfter,
        signature_algorithm: 'SHA256-RSA',
        key_algorithm: 'RSA',
        key_size: 2048,
        fingerprint: 'ab:cd:ef',
        self_signed: false,
        expired: false,
      },
    },
  })
}

/** An API asset as a scanner would send it: no auth, type or endpoint facts. */
export const scannedApiWithoutDetails = base({
  id: 'api-1',
  name: 'api.example.org',
  type: 'application',
  subType: 'api',
  metadata: {},
})

/** A record with none of the facts: every cell must say unknown. */
export const bareService = base({
  id: 'svc-bare',
  name: 'staging.example.org',
  type: 'service',
  metadata: {},
})
