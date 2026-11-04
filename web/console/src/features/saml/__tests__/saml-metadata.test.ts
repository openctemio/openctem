/**
 * SAML metadata helpers of the admin console form: the SP metadata download
 * goes through the organization-scoped admin API (built on APP_URL, never the
 * console's own address), the IdP import posts exactly one source, an
 * oversized file never leaves the browser, and a refusal reads the API's
 * reason instead of its text.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

const mockFetch = vi.fn()
const mockDownload = vi.fn()
vi.mock('@console/lib/admin-api/client', async () => {
  const actual = await vi.importActual<typeof import('@console/lib/admin-api/client')>(
    '@console/lib/admin-api/client'
  )
  return { ...actual, adminFetch: (p: string, init?: unknown) => mockFetch(p, init) }
})
vi.mock('@/lib/utils', async () => {
  const actual = await vi.importActual<typeof import('@/lib/utils')>('@/lib/utils')
  return {
    ...actual,
    downloadFile: (c: string, f: string, m: string) => mockDownload(c, f, m),
  }
})

import { AdminApiError } from '@console/lib/admin-api/client'
import {
  downloadSpMetadata,
  importIdPMetadata,
  readMetadataFile,
  MAX_IDP_METADATA_FILE_BYTES,
} from '../lib/saml-metadata'
import { metadataErrorMessage } from '../components/saml-config-form'

const t = (_key: string, fallback?: string) => fallback ?? _key

describe('SAML metadata helpers', () => {
  beforeEach(() => vi.clearAllMocks())

  it('downloads the SP metadata the API built, under its file name', async () => {
    mockFetch.mockResolvedValueOnce({
      filename: 'openctem-acme-sp-metadata.xml',
      xml: '<EntityDescriptor/>',
      base_url: 'https://app.example.com',
    })
    await downloadSpMetadata('t1')
    expect(mockFetch).toHaveBeenCalledWith('/tenants/t1/sso/saml/sp-metadata', undefined)
    expect(mockDownload).toHaveBeenCalledWith(
      '<EntityDescriptor/>',
      'openctem-acme-sp-metadata.xml',
      'application/samlmetadata+xml'
    )
  })

  it('posts one metadata source for the organization', async () => {
    mockFetch.mockResolvedValueOnce({ idp_entity_id: 'e' })
    await importIdPMetadata('t1', { metadata_url: 'https://login.example/md.xml' })
    expect(mockFetch).toHaveBeenCalledWith('/tenants/t1/sso/saml/idp-metadata', {
      method: 'POST',
      body: { metadata_url: 'https://login.example/md.xml' },
    })
  })

  it('refuses an oversized metadata file before sending it', async () => {
    // jsdom's File has no text(); the browser's does.
    const file = (size: number, text: string) =>
      ({ size, text: vi.fn(async () => text) }) as unknown as File
    const big = file(MAX_IDP_METADATA_FILE_BYTES + 1, 'x')
    expect(await readMetadataFile(big)).toBeNull()
    expect((big as unknown as { text: ReturnType<typeof vi.fn> }).text).not.toHaveBeenCalled()
    expect(await readMetadataFile(file(20, '<EntityDescriptor/>'))).toBe('<EntityDescriptor/>')
  })

  it('explains a refusal by its reason', () => {
    const err = new AdminApiError('ignored server text', 422, 'SAML_METADATA_INVALID', {
      reason: 'url_blocked',
    })
    expect(metadataErrorMessage(err, t)).toMatch(/private or internal network/)
    const doctype = new AdminApiError('x', 422, 'SAML_METADATA_INVALID', { reason: 'doctype' })
    expect(metadataErrorMessage(doctype, t)).toMatch(/document type or entities/)
  })
})
