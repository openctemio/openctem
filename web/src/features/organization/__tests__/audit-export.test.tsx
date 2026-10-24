import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'

const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_key: string, fallback: string) => fallback,
    locale: 'en',
  }),
}))
vi.mock('@/lib/api/client', () => ({ getApiBaseUrl: () => 'https://api.example.test' }))
const stepUp = vi.hoisted(() => ({ requestStepUp: vi.fn() }))
vi.mock('@/lib/api/step-up', () => ({ ...stepUp, STEP_UP_REQUIRED_CODE: 'STEP_UP_REQUIRED' }))

import { buildAuditExportUrl, downloadAuditLog } from '../api/export-audit-logs'
import { useAuditExport } from '../hooks/use-audit-export'

const FILTERS = {
  page: 3,
  per_page: 50,
  sort_by: 'severity',
  sort_order: 'asc' as const,
  search: 'login failed',
  result: ['failure' as const],
  severity: ['high' as const, 'critical' as const],
  exclude_system: true,
}

describe('buildAuditExportUrl', () => {
  it('carries the list filters, the format, and no paging or sort', () => {
    const url = new URL(buildAuditExportUrl('jsonl', FILTERS))
    expect(url.origin + url.pathname).toBe('https://api.example.test/api/v1/audit-logs/export')
    const q = url.searchParams
    expect(q.get('format')).toBe('jsonl')
    expect(q.get('search')).toBe('login failed')
    expect(q.getAll('result')).toEqual(['failure'])
    expect(q.getAll('severity')).toEqual(['high', 'critical'])
    expect(q.get('exclude_system')).toBe('true')
    for (const k of ['page', 'per_page', 'sort_by', 'sort_order']) expect(q.has(k)).toBe(false)
  })

  it('works without filters', () => {
    expect(buildAuditExportUrl('csv')).toBe(
      'https://api.example.test/api/v1/audit-logs/export?format=csv'
    )
  })
})

function mockDownload(headers: Record<string, string>, ok = true, status = 200) {
  const blob = new Blob(['a,b\n'])
  const fetchMock = vi.fn().mockResolvedValue({
    ok,
    status,
    headers: new Headers(headers),
    blob: () => Promise.resolve(blob),
    json: () => Promise.resolve({ message: 'denied for test' }),
  })
  vi.stubGlobal('fetch', fetchMock)
  URL.createObjectURL = vi.fn(() => 'blob:x')
  URL.revokeObjectURL = vi.fn()
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  return fetchMock
}

describe('downloadAuditLog', () => {
  beforeEach(() => vi.clearAllMocks())

  it('fetches with credentials (GET) and reports the file name and truncation', async () => {
    const fetchMock = mockDownload({
      'Content-Disposition': 'attachment; filename="audit-log-acme-20261018T100000Z.csv"',
      'X-Export-Truncated': 'true',
    })
    const res = await downloadAuditLog('csv', FILTERS)
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/audit-logs/export?format=csv'),
      {
        credentials: 'include',
      }
    )
    expect(res).toEqual({ filename: 'audit-log-acme-20261018T100000Z.csv', truncated: true })
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:x')
  })

  it('throws the API message on a refusal', async () => {
    mockDownload({}, false, 403)
    await expect(downloadAuditLog('csv')).rejects.toThrow('denied for test')
  })
})

describe('useAuditExport', () => {
  beforeEach(() => vi.clearAllMocks())

  it('warns when the export was truncated', async () => {
    mockDownload({ 'X-Export-Truncated': 'true' })
    const { result } = renderHook(() => useAuditExport(FILTERS))
    await act(() => result.current.run('csv'))
    expect(toast.warning).toHaveBeenCalledWith(
      'Only the newest 50,000 events were exported; narrow the filters.'
    )
    expect(toast.success).not.toHaveBeenCalled()
  })

  it('confirms a complete export without the warning', async () => {
    mockDownload({ 'X-Export-Truncated': 'false' })
    const { result } = renderHook(() => useAuditExport(FILTERS))
    await act(() => result.current.run('jsonl'))
    expect(toast.success).toHaveBeenCalledWith('Audit log exported')
    expect(toast.warning).not.toHaveBeenCalled()
  })

  it('shows the failure', async () => {
    mockDownload({}, false, 403)
    const { result } = renderHook(() => useAuditExport(FILTERS))
    await act(() => result.current.run('csv'))
    expect(toast.error).toHaveBeenCalled()
    expect(result.current.isExporting).toBe(false)
  })
})

describe('downloadAuditLog step-up', () => {
  function response(status: number, body: unknown) {
    const r = {
      ok: status < 400,
      status,
      headers: new Headers({ 'Content-Disposition': 'attachment; filename="audit.csv"' }),
      blob: () => Promise.resolve(new Blob(['a\n'])),
      json: () => Promise.resolve(body),
    }
    return { ...r, clone: () => r }
  }

  beforeEach(() => {
    vi.restoreAllMocks()
    stepUp.requestStepUp.mockReset()
    URL.createObjectURL = vi.fn(() => 'blob:x')
    URL.revokeObjectURL = vi.fn()
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  })

  it('asks for verification and retries once when the API requires step-up', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(response(403, { code: 'STEP_UP_REQUIRED', message: 'verify' }))
      .mockResolvedValueOnce(response(200, {}))
    vi.stubGlobal('fetch', fetchMock)
    stepUp.requestStepUp.mockResolvedValue(true)
    const res = await downloadAuditLog('csv')
    expect(stepUp.requestStepUp).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(res.filename).toBe('audit.csv')
  })

  it('does not download when verification is cancelled', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(response(403, { code: 'STEP_UP_REQUIRED', message: 'verify' }))
    vi.stubGlobal('fetch', fetchMock)
    stepUp.requestStepUp.mockResolvedValue(false)
    await expect(downloadAuditLog('csv')).rejects.toThrow('verify')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('does not ask for verification on another refusal', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(response(403, { code: 'FORBIDDEN', message: 'no' }))
    )
    await expect(downloadAuditLog('csv')).rejects.toThrow('no')
    expect(stepUp.requestStepUp).not.toHaveBeenCalled()
  })
})
