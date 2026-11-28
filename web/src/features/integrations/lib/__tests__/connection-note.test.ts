import { describe, expect, it } from 'vitest'

import { en, vi } from '@/lib/i18n/dictionaries'
import { connectionNote } from '../connection-status'

function translator(locale: 'en' | 'vi') {
  const dict: Record<string, string> = locale === 'vi' ? vi : en
  return (key: string, fallback?: string, vars?: Record<string, string | number>) => {
    let s = dict[key] ?? fallback ?? key
    for (const [k, v] of Object.entries(vars ?? {})) s = s.replaceAll(`{${k}}`, String(v))
    return s
  }
}

const NOT_FOUND = {
  status: 'error',
  status_code: 'INTEGRATION_NOT_FOUND',
  status_message:
    'The service did not find what this connection points at. Check the address and project.',
}

describe('connectionNote', () => {
  it('words a failure from its code in the reader language', () => {
    const note = connectionNote(NOT_FOUND, translator('vi'), 'vi')
    expect(note?.tone).toBe('error')
    expect(note?.text).toBe(vi['errors.INTEGRATION_NOT_FOUND'])
    expect(note?.text).not.toMatch(/did not find/)
  })

  it('shows when a member turned it off as a local date, never the raw ISO text', () => {
    for (const row of [
      // Rows written before the code existed.
      { status: 'disabled', status_message: 'Disabled by user at 2026-11-27T08:59:36Z' },
      {
        status: 'disabled',
        status_code: 'INTEGRATION_DISABLED_BY_USER',
        status_message: 'Disabled by user at 2026-11-27T08:59:36Z',
      },
    ]) {
      const note = connectionNote(row, translator('vi'), 'vi')
      expect(note?.tone).toBe('muted')
      expect(note?.text).toMatch(/^Đã tắt lúc /)
      expect(note?.text).not.toMatch(/2026-11-27T|Disabled by user/)
    }
  })

  it('says nothing for a healthy connection', () => {
    expect(connectionNote({ status: 'connected' }, translator('en'), 'en')).toBeNull()
  })

  it('never shows an unsafe stored sentence (older rows can hold upstream text)', () => {
    const note = connectionNote(
      { status: 'error', status_message: 'dial tcp 10.0.0.5:443: i/o timeout' },
      translator('en'),
      'en'
    )
    expect(note?.text).toBe(en['errors.INTEGRATION_TEST_FAILED'])
  })
})
