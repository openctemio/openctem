import { beforeEach, describe, expect, it } from 'vitest'

import {
  clearFormDrafts,
  PENTEST_FINDING_DRAFT_KEY,
  PENTEST_TEMPLATE_DRAFT_KEY,
} from '../form-drafts'
import { useAuthStore } from '@/stores/auth-store'

describe('form drafts', () => {
  beforeEach(() => {
    localStorage.clear()
    localStorage.setItem(PENTEST_FINDING_DRAFT_KEY, JSON.stringify({ title: 'SQLi PoC' }))
    localStorage.setItem(PENTEST_TEMPLATE_DRAFT_KEY, JSON.stringify({ name: 'XSS' }))
    localStorage.setItem('unrelated', 'keep')
  })

  it('clearFormDrafts removes every draft and nothing else', () => {
    clearFormDrafts()
    expect(localStorage.getItem(PENTEST_FINDING_DRAFT_KEY)).toBeNull()
    expect(localStorage.getItem(PENTEST_TEMPLATE_DRAFT_KEY)).toBeNull()
    expect(localStorage.getItem('unrelated')).toBe('keep')
  })

  it('ending the session drops the drafts, so the next user is not offered them', () => {
    useAuthStore.getState().clearAuth()
    expect(localStorage.getItem(PENTEST_FINDING_DRAFT_KEY)).toBeNull()
    expect(localStorage.getItem(PENTEST_TEMPLATE_DRAFT_KEY)).toBeNull()
  })
})
