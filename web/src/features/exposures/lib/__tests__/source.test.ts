import { describe, expect, it } from 'vitest'
import { translate } from '@/lib/i18n'
import { en as enDict } from '@/lib/i18n/dictionaries/en'
import { vi as viDict } from '@/lib/i18n/dictionaries/vi'
import { exposureSourceLabel } from '../source'

const tEn = (key: string, fallback?: string, vars?: Record<string, string | number>) =>
  translate(enDict, key, fallback, vars, 'en')
const tVi = (key: string, fallback?: string, vars?: Record<string, string | number>) =>
  translate(viDict, key, fallback, vars, 'vi')

// The sources the server writes (server/internal/app: easmdns, exposurebridge,
// certmonitor, easm, contentrule, pagemon; credential imports).
const SERVER_SOURCES = [
  'easm_dns',
  'recon_scan',
  'cert_transparency',
  'certificate_san',
  'easm_lookalike',
  'detection-rules',
  'secret_scan',
  'misconfig_scan',
  'page_monitoring',
  'paste_site',
  'data_breach - Example breach',
]

describe('exposureSourceLabel', () => {
  it('words every source code the server writes, in English and Vietnamese', () => {
    for (const source of SERVER_SOURCES) {
      const en = exposureSourceLabel(tEn, source)
      const vi = exposureSourceLabel(tVi, source)
      expect(en, source).not.toMatch(/_|^[a-z]/)
      expect(vi, source).not.toBe(en)
    }
  })

  it('keeps a leaked credential source its own name', () => {
    expect(exposureSourceLabel(tEn, 'paste_site')).toBe('Paste site')
    expect(exposureSourceLabel(tEn, 'data_breach - Example breach')).toBe(
      'Data breach: Example breach'
    )
    expect(exposureSourceLabel(tVi, 'data_breach - Example breach')).toBe(
      'Vụ xâm phạm dữ liệu: Example breach'
    )
  })

  it('shows a source it does not know as written', () => {
    expect(exposureSourceLabel(tEn, 'acme-importer')).toBe('acme-importer')
    expect(exposureSourceLabel(tEn, 'new_kind - x')).toBe('new_kind - x')
    expect(exposureSourceLabel(tEn, '')).toBe('')
    expect(exposureSourceLabel(tEn, undefined)).toBe('')
  })
})
