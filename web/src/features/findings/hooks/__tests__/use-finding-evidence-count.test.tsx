import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import type { FindingDetail } from '../../types'

let tool: unknown[] = []
let validation: unknown[] = []
let uploads: unknown[] = []

vi.mock('../../api/use-finding-evidence-items', () => ({
  useFindingEvidenceItems: () => ({ data: { data: tool } }),
}))
vi.mock('../../api/use-findings-api', () => ({
  useFindingValidationEvidenceApi: () => ({ data: { evidence: validation } }),
}))
vi.mock('../../api/use-finding-attachments', () => ({
  useFindingAttachments: () => ({ data: { data: uploads } }),
}))

const { useFindingEvidenceCount } = await import('../use-finding-evidence-count')

const base = { id: 'f1', source: 'pentest', evidence: [] } as unknown as FindingDetail

describe('useFindingEvidenceCount', () => {
  beforeEach(() => {
    tool = []
    validation = []
    uploads = []
  })

  it('is 0 for a finding with no evidence and for no finding', () => {
    expect(renderHook(() => useFindingEvidenceCount(base)).result.current).toBe(0)
    expect(renderHook(() => useFindingEvidenceCount(null)).result.current).toBe(0)
  })

  it('counts a finding that only has validation evidence', () => {
    validation = [{ id: 'v1' }, { id: 'v2' }]
    expect(renderHook(() => useFindingEvidenceCount(base)).result.current).toBe(2)
  })

  it('adds tool evidence, validation, uploaded files, notes, code and stacks', () => {
    tool = [{}, {}]
    validation = [{}]
    uploads = [{}]
    const f = {
      ...base,
      evidence: [{ id: 'n1' }],
      snippet: 'x',
      stacks: [{}],
      attachments: [{}],
    } as unknown as FindingDetail
    expect(renderHook(() => useFindingEvidenceCount(f)).result.current).toBe(
      2 + 1 + 1 + 1 + 1 + 1 + 1
    )
  })
})
