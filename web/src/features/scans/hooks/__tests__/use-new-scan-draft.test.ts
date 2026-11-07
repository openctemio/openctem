import { afterEach, describe, expect, it } from 'vitest'
import { DEFAULT_NEW_SCAN } from '../../types'
import { clearNewScanDraft, loadNewScanDraft, saveNewScanDraft } from '../use-new-scan-draft'

const form = {
  ...DEFAULT_NEW_SCAN,
  name: 'Weekly web',
  targets: { ...DEFAULT_NEW_SCAN.targets, customTargets: ['app.example.com'] },
}

afterEach(() => window.sessionStorage.clear())

describe('new scan draft', () => {
  it('is restored for the same organization and user, with its step', () => {
    saveNewScanDraft('t1', { form, step: 'schedule' }, 'u1')
    expect(loadNewScanDraft('t1', 'u1')).toEqual({ form, step: 'schedule' })
  })

  it('is never shown to another user or in another organization', () => {
    saveNewScanDraft('t1', { form, step: 'targets' }, 'u1')
    expect(loadNewScanDraft('t1', 'u2')).toBeNull()
    expect(loadNewScanDraft('t2', 'u1')).toBeNull()
  })

  it('is kept in this tab only (sessionStorage, not localStorage)', () => {
    saveNewScanDraft('t1', { form, step: 'targets' }, 'u1')
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(1)
  })

  it('is gone once cleared (created or discarded)', () => {
    saveNewScanDraft('t1', { form, step: 'targets' }, 'u1')
    clearNewScanDraft('t1', 'u1')
    expect(loadNewScanDraft('t1', 'u1')).toBeNull()
  })

  it('ignores a damaged entry', () => {
    window.sessionStorage.setItem('openctem:new-scan-draft:t1:u1', '{not json')
    expect(loadNewScanDraft('t1', 'u1')).toBeNull()
  })
})
