import { describe, it, expect, vi } from 'vitest'

import { buildCsv } from '@/hooks/use-csv-export'
import { RUN_EXPORT_FIELDS, fetchRunsForExport } from '../export-runs'
import type { PipelineRun } from '@/lib/api/pipeline-types'

const run = (i: number, over: Partial<PipelineRun> = {}): PipelineRun => ({
  id: `r${i}`,
  tenant_id: 't',
  pipeline_id: 'p',
  scan_id: 's1',
  scan_name: 'Nightly recon',
  trigger_type: 'manual',
  status: 'completed',
  total_steps: 1,
  completed_steps: 1,
  failed_steps: 0,
  skipped_steps: 0,
  total_findings: 0,
  created_at: '2026-10-04T10:00:00Z',
  ...over,
})

function pages(total: number) {
  return vi.fn(async (url: string) => {
    const u = new URL(url, 'http://x')
    const page = Number(u.searchParams.get('page'))
    const per = Number(u.searchParams.get('per_page'))
    const start = (page - 1) * per
    const n = Math.max(0, Math.min(per, total - start))
    return {
      items: Array.from({ length: n }, (_, i) => run(start + i)),
      total,
      page,
      per_page: per,
      total_pages: Math.ceil(total / per),
    }
  })
}

describe('fetchRunsForExport', () => {
  it('reads the same list the table shows: same endpoint, filter and sort, page by page', async () => {
    const fetchPage = pages(250)
    const out = await fetchRunsForExport(
      { status: 'failed', sort: '-total_findings' },
      5000,
      fetchPage
    )
    expect(out.runs).toHaveLength(250)
    expect(out.capped).toBe(false)
    expect(fetchPage).toHaveBeenCalledTimes(3)
    for (const [url] of fetchPage.mock.calls) {
      expect(url.startsWith('/api/v1/pipeline-runs?')).toBe(true)
      const q = new URL(url, 'http://x').searchParams
      expect(q.get('status')).toBe('failed')
      expect(q.get('sort')).toBe('-total_findings')
      expect(q.get('per_page')).toBe('100')
    }
  })

  it('stops at the cap and says so', async () => {
    const fetchPage = pages(10_000)
    const out = await fetchRunsForExport({}, 300, fetchPage)
    expect(out.runs).toHaveLength(300)
    expect(out.total).toBe(10_000)
    expect(out.capped).toBe(true)
    expect(fetchPage).toHaveBeenCalledTimes(3)
  })
})

describe('run export cells', () => {
  it('cannot smuggle a spreadsheet formula or shift columns', () => {
    const hostile = run(1, {
      scan_name: '=HYPERLINK("http://evil","x")',
      error_message: '@SUM(1,2)\nsecond line',
    })
    const csv = buildCsv(
      RUN_EXPORT_FIELDS.map((f) => f.header),
      [RUN_EXPORT_FIELDS.map((f) => f.accessor(hostile))]
    )
    expect(csv).toContain(`"'=HYPERLINK(""http://evil"",""x"")"`)
    expect(csv).toContain(`"'@SUM(1,2)\nsecond line"`)
    // Same number of columns in the header and the row.
    const [header] = csv.split('\n')
    expect(header.split(',')).toHaveLength(RUN_EXPORT_FIELDS.length)
  })

  it('names deleted scans and pipeline runs', () => {
    const scanCol = RUN_EXPORT_FIELDS.find((f) => f.header === 'Scan')!
    expect(scanCol.accessor(run(1, { scan_name: undefined }))).toBe('Deleted scan')
    expect(scanCol.accessor(run(1, { scan_id: undefined, scan_name: undefined }))).toBe(
      'Pipeline run'
    )
  })
})
