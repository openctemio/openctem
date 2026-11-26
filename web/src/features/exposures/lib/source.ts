/**
 * An exposure's source in the reader's language.
 *
 * The API returns the source as the server wrote it: a platform check's
 * code (`easm_dns`, `cert_transparency`, `secret_scan`, ...) or, for a
 * leaked credential, the credential source type and the source's own name
 * (`paste_site`, `data_breach - Example breach`). Each code has words here;
 * a source's own name stays as written, and a source this build does not
 * know (an import or an API client names its own) is shown as written.
 */
import { isCredentialSource } from '@/features/credentials/components/credential-list-parts'

type T = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/** The platform's own checks that raise exposures (server constants). */
const PLATFORM_SOURCES: Record<string, string> = {
  easm_dns: 'DNS checks',
  recon_scan: 'Discovery scan',
  cert_transparency: 'Certificate logs',
  certificate_san: 'Certificate names',
  easm_lookalike: 'Look-alike domains',
  'detection-rules': 'Detection rules',
  secret_scan: 'Secret scan',
  misconfig_scan: 'Configuration scan',
  page_monitoring: 'Page monitoring',
}

/** "<credential source type>" or "<credential source type> - <name>". */
const CREDENTIAL_SOURCE = /^([a-z_]+)(?: - (.+))?$/

export function exposureSourceLabel(t: T, source: string | null | undefined): string {
  const text = source?.trim() ?? ''
  if (!text) return ''
  const platform = PLATFORM_SOURCES[text]
  if (platform) return t(`exposures.source.${text.replace(/-/g, '_')}`, platform)
  const m = CREDENTIAL_SOURCE.exec(text)
  if (m && isCredentialSource(m[1])) {
    const kind = t(`credentials.source.${m[1]}`, m[1])
    const name = m[2]?.trim()
    return name ? t('exposures.source.named', '{kind}: {name}', { kind, name }) : kind
  }
  return text
}
