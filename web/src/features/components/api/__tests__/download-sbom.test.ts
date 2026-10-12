import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { downloadSbom, sbomFileName, sbomUrl } from '../download-sbom'

describe('sbomUrl / sbomFileName', () => {
  it('asks the API for the format (and one asset when given)', () => {
    expect(sbomUrl('cyclonedx')).toBe('/api/v1/components/sbom?format=cyclonedx')
    expect(sbomUrl('spdx', 'a-1')).toBe('/api/v1/components/sbom?format=spdx&asset_id=a-1')
  })

  it('names the file by the format convention', () => {
    const d = new Date('2026-10-08T12:00:00Z')
    expect(sbomFileName('cyclonedx', d)).toBe('sbom-2026-10-08.cdx.json')
    expect(sbomFileName('spdx', d)).toBe('sbom-2026-10-08.spdx.json')
  })
})

describe('downloadSbom', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    URL.createObjectURL = vi.fn(() => 'blob:x')
    URL.revokeObjectURL = vi.fn()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  it('saves what the server built, with no client-side document or delay', async () => {
    fetchMock.mockResolvedValue(new Response('{"bomFormat":"CycloneDX"}', { status: 200 }))
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    const name = await downloadSbom('cyclonedx')

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/components/sbom?format=cyclonedx', {
      credentials: 'include',
    })
    expect(name).toMatch(/\.cdx\.json$/)
    expect(click).toHaveBeenCalledTimes(1)
    expect(URL.revokeObjectURL).toHaveBeenCalled()
  })

  it('throws the API message on an error', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ message: 'more than 10000 components' }), { status: 400 })
    )
    await expect(downloadSbom('spdx')).rejects.toThrow('more than 10000 components')
  })
})
