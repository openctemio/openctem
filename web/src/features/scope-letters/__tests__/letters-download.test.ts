import { describe, it, expect, vi, afterEach } from 'vitest'

vi.mock('@/lib/api/client', () => ({
  csrfFetch: vi.fn(),
  get: vi.fn(),
  post: vi.fn(),
  getApiBaseUrl: () => 'http://api.test',
}))

import { downloadLetter, letterFileExtension } from '../api/letters-api'

describe('letterFileExtension', () => {
  it('maps the served letter types', () => {
    expect(letterFileExtension('application/pdf')).toBe('.pdf')
    expect(letterFileExtension('image/png; charset=binary')).toBe('.png')
    expect(letterFileExtension('image/jpeg')).toBe('.jpg')
    expect(letterFileExtension('application/octet-stream')).toBe('')
    expect(letterFileExtension(null)).toBe('')
  })
})

describe('downloadLetter', () => {
  afterEach(() => vi.restoreAllMocks())

  it('saves a PDF letter with a .pdf extension', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(new Blob(['x']), { headers: { 'Content-Type': 'application/pdf' } })
      )
    )
    URL.createObjectURL = vi.fn(() => 'blob:x')
    URL.revokeObjectURL = vi.fn()
    let name = ''
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement
    ) {
      name = this.download
    })
    await downloadLetter({ id: 'l1', title: 'Acme letter' } as never)
    expect(name).toBe('Acme_letter.pdf')
  })
})
