import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { downloadFindingsExport, exportTruncated } from '../export-findings'
import { ApiClientError } from '@/lib/api/error-handler'

const fetchMock = vi.fn()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  URL.createObjectURL = vi.fn(() => 'blob:x')
  URL.revokeObjectURL = vi.fn()
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
})
afterEach(() => {
  fetchMock.mockReset()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('downloadFindingsExport', () => {
  it('saves the file and reports the cap the API stated', async () => {
    fetchMock.mockResolvedValue(
      new Response('id,title\n', {
        status: 200,
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': 'attachment; filename="findings-x.csv"',
          'X-Export-Max-Rows': '10000',
        },
      })
    )
    const res = await downloadFindingsExport('/api/v1/findings/export?format=csv', 'csv')
    expect(res).toEqual({ filename: 'findings-x.csv', maxRows: 10000 })
    expect(fetchMock.mock.calls[0][1]).toEqual({ credentials: 'include' })
  })

  it('turns a refusal into an ApiClientError with its details', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          error: {
            code: 'FORBIDDEN',
            message: 'forbidden',
            details: { missing_permissions: ['findings:export'] },
            request_id: 'req-1',
          },
        }),
        { status: 403, headers: { 'Content-Type': 'application/json' } }
      )
    )
    const err = await downloadFindingsExport('/x', 'csv').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiClientError)
    expect(err).toMatchObject({
      statusCode: 403,
      code: 'FORBIDDEN',
      details: { missing_permissions: ['findings:export'] },
      requestId: 'req-1',
    })
  })
})

describe('exportTruncated', () => {
  it('compares the list total with the cap', () => {
    expect(exportTruncated(25000, 10000)).toBe(true)
    expect(exportTruncated(10000, 10000)).toBe(false)
    expect(exportTruncated(undefined, 10000)).toBe(false)
    expect(exportTruncated(25000, undefined)).toBe(false)
  })
})
