import { describe, expect, it } from 'vitest'
import { isBinaryContentType } from '../proxy-binary'

describe('isBinaryContentType', () => {
  it('passes office documents and other files through as bytes', () => {
    for (const ct of [
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/pdf',
      'application/zip',
      'application/octet-stream',
      'image/png',
    ]) {
      expect(isBinaryContentType(ct)).toBe(true)
    }
  })
  it('decodes JSON and text', () => {
    for (const ct of [
      'application/json',
      'application/json; charset=utf-8',
      'application/problem+json',
      'text/plain',
      'text/csv; charset=utf-8',
      '',
    ]) {
      expect(isBinaryContentType(ct)).toBe(false)
    }
  })
})
