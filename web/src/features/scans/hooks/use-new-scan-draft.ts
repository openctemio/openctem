'use client'

/**
 * Keeps the New Scan wizard's state while the user leaves it to approve a
 * scope entry, verify a domain or change a tier, and gives it back when they
 * open New Scan again. Stored per tab (sessionStorage) and per organization,
 * cleared when the scan is saved or the user cancels. Only the form is kept
 * (names, targets, options); nothing secret is in it. Storage may be missing
 * or blocked: the wizard then simply starts empty.
 */

import type { NewScanFormData } from '../types'

const KEY = 'openctem:new-scan-draft:'

export interface NewScanDraft {
  form: NewScanFormData
  step: string
}

export function loadNewScanDraft(tenantId: string | undefined): NewScanDraft | null {
  if (!tenantId) return null
  try {
    const raw = window.sessionStorage.getItem(KEY + tenantId)
    if (!raw) return null
    const parsed = JSON.parse(raw) as Partial<NewScanDraft>
    if (!parsed?.form || typeof parsed.form !== 'object' || typeof parsed.step !== 'string')
      return null
    return parsed as NewScanDraft
  } catch {
    return null
  }
}

export function saveNewScanDraft(tenantId: string | undefined, draft: NewScanDraft): void {
  if (!tenantId) return
  try {
    window.sessionStorage.setItem(KEY + tenantId, JSON.stringify(draft))
  } catch {
    // Storage full or blocked: nothing to keep.
  }
}

export function clearNewScanDraft(tenantId: string | undefined): void {
  if (!tenantId) return
  try {
    window.sessionStorage.removeItem(KEY + tenantId)
  } catch {
    // Nothing stored.
  }
}
