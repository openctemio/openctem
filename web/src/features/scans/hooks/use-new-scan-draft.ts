'use client'

/**
 * Keeps the New Scan wizard's state while the user leaves it to approve a
 * scope entry, verify a domain or change a tier, and gives it back when they
 * open New Scan again. Stored per tab (sessionStorage, never localStorage: a
 * target list is organization data and must not outlive the tab), per
 * organization and per user, cleared when the scan is saved or discarded;
 * closing with "Keep as draft" keeps it. Only the form is kept
 * (names, targets, options); nothing secret is in it. Storage may be missing
 * or blocked: the wizard then simply starts empty.
 */

import type { NewScanFormData } from '../types'

const KEY = 'openctem:new-scan-draft:'

export interface NewScanDraft {
  form: NewScanFormData
  step: string
}

function keyOf(tenantId: string, userId?: string): string {
  return userId ? `${KEY}${tenantId}:${userId}` : KEY + tenantId
}

export function loadNewScanDraft(
  tenantId: string | undefined,
  userId?: string
): NewScanDraft | null {
  if (!tenantId) return null
  try {
    const raw = window.sessionStorage.getItem(keyOf(tenantId, userId))
    if (!raw) return null
    const parsed = JSON.parse(raw) as Partial<NewScanDraft>
    if (!parsed?.form || typeof parsed.form !== 'object' || typeof parsed.step !== 'string')
      return null
    return parsed as NewScanDraft
  } catch {
    return null
  }
}

export function saveNewScanDraft(
  tenantId: string | undefined,
  draft: NewScanDraft,
  userId?: string
): void {
  if (!tenantId) return
  try {
    window.sessionStorage.setItem(keyOf(tenantId, userId), JSON.stringify(draft))
  } catch {
    // Storage full or blocked: nothing to keep.
  }
}

export function clearNewScanDraft(tenantId: string | undefined, userId?: string): void {
  if (!tenantId) return
  try {
    window.sessionStorage.removeItem(keyOf(tenantId, userId))
  } catch {
    // Nothing stored.
  }
}
