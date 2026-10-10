import { describe, expect, it, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'

let scopeResults: { target: string; allowed: boolean }[] = []
vi.mock('@/features/scope', () => ({
  useScopeCheck: () => ({
    available: true,
    results: scopeResults,
    isLoading: false,
    error: null,
    recheck: vi.fn(),
  }),
}))
let wfData: unknown = undefined
vi.mock('../../components/new-scan/workflow-preview', () => ({
  useWorkflowPreview: () => ({ data: wfData, error: null, isLoading: false, ready: true }),
}))
vi.mock('@/hooks/use-debounce', () => ({ useDebounce: (v: unknown) => v }))

import { useScanReview } from '../use-scan-review'
import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../../types'
import { formDataToCreateRequest } from '../../lib/scan-form'

const form = (over: Partial<NewScanFormData> = {}): NewScanFormData => ({
  ...DEFAULT_NEW_SCAN,
  name: 'Weekly',
  scannerName: 'nuclei',
  targets: { ...DEFAULT_NEW_SCAN.targets, customTargets: ['a.example.com', 'b.example.com'] },
  ...over,
})
const review = (f: NewScanFormData) =>
  renderHook(() => useScanReview(f, { scan_workflow_id: 'w1' }, true)).result.current

describe('useScanReview', () => {
  beforeEach(() => {
    scopeResults = []
    wfData = undefined
  })

  it('has no blocker when the form is complete and every target is in scope', () => {
    scopeResults = [
      { target: 'a.example.com', allowed: true },
      { target: 'b.example.com', allowed: true },
    ]
    expect(review(form()).blockers).toEqual([])
  })

  it('blocks on a refused target (create refuses the whole request) and names it', () => {
    scopeResults = [
      { target: 'a.example.com', allowed: true },
      { target: 'b.example.com', allowed: false },
    ]
    const r = review(form())
    expect(r.refused).toEqual(['b.example.com'])
    expect(r.blockers[0]).toMatch(/1 target may not be scanned/)
  })

  it('blocks on the form problems and on a blocking workflow step', () => {
    wfData = { blocking: true, nodes: [{ blocking: { message: 'no sensor runs httpx' } }] }
    const r = review(form({ name: '', mode: 'workflow', workflowId: 'w1' }))
    expect(r.blockers).toContain('Please enter a scan name')
    expect(r.blockers).toContain('The workflow would not start: no sensor runs httpx')
  })

  it('warns about targets waiting for their windows and about groups resolved at run time', () => {
    wfData = {
      blocking: false,
      targets: { windows: { waiting_count: 2, never_count: 0, waiting: [], never: [] } },
    }
    const r = review(
      form({
        mode: 'workflow',
        workflowId: 'w1',
        targets: { ...DEFAULT_NEW_SCAN.targets, assetGroupIds: ['g1'] },
      })
    )
    expect(r.warnings.join(' ')).toMatch(/2 targets wait for their scan windows/)
    expect(r.warnings.join(' ')).toMatch(/resolved when the scan runs/)
    expect(r.blockers).toEqual([])
  })

  it('blocks a scan whose targets have windows that never open', () => {
    wfData = {
      blocking: false,
      targets: { windows: { waiting_count: 0, never_count: 1, waiting: [], never: [] } },
    }
    const r = review(form({ mode: 'workflow', workflowId: 'w1' }))
    expect(r.blockers.join(' ')).toMatch(/1 targets have scan windows that never open/)
  })
})

describe('save without running', () => {
  it('creates a manual scan with no schedule fields', () => {
    const req = formDataToCreateRequest(
      form({
        schedule: { ...DEFAULT_NEW_SCAN.schedule, runImmediately: false, saveOnly: true },
      })
    )
    expect(req.schedule_type).toBe('manual')
    expect(req.timezone).toBeUndefined()
    expect(req.schedule_time).toBeUndefined()
  })
})
