/**
 * "Create scan, start when scope is approved" is offered only when every
 * refused target only waits for a pending scope entry; the New Scan draft
 * survives leaving the wizard, per organization.
 */
import { afterEach, describe, expect, it } from 'vitest'
import { onlyAwaitingApproval } from '../scope-wait'
import {
  clearNewScanDraft,
  loadNewScanDraft,
  saveNewScanDraft,
} from '../../hooks/use-new-scan-draft'
import { DEFAULT_NEW_SCAN } from '../../types'

describe('onlyAwaitingApproval', () => {
  it('needs refusals, all of them entry_pending', () => {
    expect(onlyAwaitingApproval(undefined)).toBe(false)
    expect(onlyAwaitingApproval([{ target: 'a', allowed: true }])).toBe(false)
    expect(
      onlyAwaitingApproval([
        { target: 'a', allowed: true },
        { target: '*.acme.vn', allowed: false, code: 'entry_pending' },
      ])
    ).toBe(true)
    expect(
      onlyAwaitingApproval([
        { target: '*.acme.vn', allowed: false, code: 'entry_pending' },
        { target: 'x.io', allowed: false, code: 'no_entry' },
      ])
    ).toBe(false)
  })
})

describe('New Scan draft', () => {
  afterEach(() => window.sessionStorage.clear())

  it('keeps the form per organization until cleared', () => {
    const form = { ...DEFAULT_NEW_SCAN, name: 'vnd weekly' }
    saveNewScanDraft('t1', { form, step: 'targets' })
    expect(loadNewScanDraft('t1')).toEqual({ form, step: 'targets' })
    expect(loadNewScanDraft('t2')).toBeNull()
    clearNewScanDraft('t1')
    expect(loadNewScanDraft('t1')).toBeNull()
  })

  it('ignores a broken or foreign value', () => {
    window.sessionStorage.setItem('openctem:new-scan-draft:t1', '{nope')
    expect(loadNewScanDraft('t1')).toBeNull()
    window.sessionStorage.setItem('openctem:new-scan-draft:t1', JSON.stringify({ form: 1 }))
    expect(loadNewScanDraft('t1')).toBeNull()
    expect(loadNewScanDraft(undefined)).toBeNull()
  })
})
