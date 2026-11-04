/**
 * SAML metadata helpers for the admin console SAML form: download this
 * organization's service-provider metadata (to upload in the IdP's SAML
 * application), and read the IdP side from its federation metadata (URL or
 * uploaded file) through the API, which fetches and parses it safely and
 * stores nothing.
 */

import { downloadFile } from '@/lib/utils'
import { adminFetch } from '@console/lib/admin-api/client'

/** Largest metadata file the form sends (the API refuses more than 1 MiB). */
export const MAX_IDP_METADATA_FILE_BYTES = 1024 * 1024

/** The organization's SP metadata, built by the API on its public address. */
export interface SpMetadata {
  filename: string
  xml: string
  base_url: string
}

/**
 * Downloads the organization's SP metadata as an XML file. The API builds it
 * on APP_URL (the console's own address is not where the IdP posts).
 */
export async function downloadSpMetadata(tenantId: string): Promise<void> {
  const md = await adminFetch<SpMetadata>(`/tenants/${tenantId}/sso/saml/sp-metadata`)
  downloadFile(md.xml, md.filename, 'application/samlmetadata+xml')
}

export interface IdPMetadataCertificate {
  pem: string
  subject: string
  not_after: string
  sha256: string
}

/** The IdP side read from metadata (POST .../sso/saml/idp-metadata). */
export interface IdPMetadata {
  idp_entity_id: string
  idp_sso_url: string
  idp_sso_binding: string
  /** The certificates joined as the SAML configuration stores them. */
  idp_certificate: string
  certificates: IdPMetadataCertificate[]
}

export type IdPMetadataSource = { metadata_url: string } | { metadata_xml: string }

/** Reads the IdP metadata through the API. Nothing is saved. */
export function importIdPMetadata(tenantId: string, source: IdPMetadataSource) {
  return adminFetch<IdPMetadata>(`/tenants/${tenantId}/sso/saml/idp-metadata`, {
    method: 'POST',
    body: source,
  })
}

/** Reads an uploaded metadata file, refusing one over the size cap. */
export async function readMetadataFile(file: File): Promise<string | null> {
  if (file.size > MAX_IDP_METADATA_FILE_BYTES) return null
  return file.text()
}
