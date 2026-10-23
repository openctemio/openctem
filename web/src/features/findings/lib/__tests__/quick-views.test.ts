import { describe, expect, it } from 'vitest'
import {
  QUICK_VIEW_KEYS,
  QUICK_VIEW_LABELS,
  knownQuickViews,
  quickViewHref,
  quickViewIsActive,
  type QuickView,
} from '../quick-views'
import { en, vi } from '@/lib/i18n/dictionaries'

const view = (key: string, params: string, count = 1): QuickView => ({ key, count, params })
const ACTIVE = view('active', 'state=open')
const TRIAGE = view('needs_triage', 'status=new')
const MINE = view('my_queue', 'state=open&related_to=me')
const SLA = view('sla_breached', 'state=open&sla_status=overdue,exceeded')
const PENDING = view('pending_approval', 'pending_approval=true')
const ACCEPTED = view('accepted_expiring', 'status=accepted&acceptance_expires_at_lte=P30D')
const CLOSED = view('closed', 'state=closed')

describe('quickViewHref', () => {
  it('links to the list with the API params', () => {
    expect(quickViewHref(ACTIVE.params)).toBe('/findings?state=open')
    expect(quickViewHref(CLOSED.params)).toBe('/findings?state=closed')
  })

  it('opens a view with no state of its own across every state', () => {
    expect(quickViewHref(TRIAGE.params)).toBe('/findings?status=new&state=all')
    expect(quickViewHref(PENDING.params)).toBe('/findings?pending_approval=true&state=all')
    expect(quickViewHref(ACCEPTED.params)).toContain('state=all')
  })

  it('keeps a comma list of values intact', () => {
    expect(new URLSearchParams(quickViewHref(SLA.params).split('?')[1]).get('sla_status')).toBe(
      'overdue,exceeded'
    )
  })
})

describe('quickViewIsActive', () => {
  const cases: Array<[string, string, QuickView, boolean]> = [
    ['plain list is Active', '', ACTIVE, true],
    ['explicit state=open is Active', 'state=open', ACTIVE, true],
    [
      'page, sort, search and grouping do not matter',
      'page=3&sort=-created_at&q=x&group=cve_id',
      ACTIVE,
      true,
    ],
    ['an extra filter is no longer the view', 'severity=high', ACTIVE, false],
    ['the link the view makes is the view', 'status=new&state=all', TRIAGE, true],
    ['the same filter under the open lens is not the view', 'status=new', TRIAGE, false],
    ['plain list is not Needs triage', '', TRIAGE, false],
    ['my queue', 'state=open&related_to=me', MINE, true],
    ['my queue plus a severity is custom', 'state=open&related_to=me&severity=low', MINE, false],
    ['sla breached', 'state=open&sla_status=overdue,exceeded', SLA, true],
    ['sla breached with one status only is custom', 'state=open&sla_status=overdue', SLA, false],
    ['pending approval', 'pending_approval=true&state=all', PENDING, true],
    [
      'accepted expiring',
      'status=accepted&acceptance_expires_at_lte=P30D&state=all',
      ACCEPTED,
      true,
    ],
    [
      'accepted expiring with another horizon is custom',
      'status=accepted&acceptance_expires_at_lte=P7D&state=all',
      ACCEPTED,
      false,
    ],
    ['closed', 'state=closed', CLOSED, true],
    ['closed is not Active', 'state=closed', ACTIVE, false],
  ]
  for (const [name, search, v, want] of cases) {
    it(name, () => expect(quickViewIsActive(search, v)).toBe(want))
  }

  it('accepts URLSearchParams', () => {
    expect(quickViewIsActive(new URLSearchParams('state=closed'), CLOSED)).toBe(true)
  })
})

describe('knownQuickViews', () => {
  it('drops a view the console cannot label and keeps the API order', () => {
    const got = knownQuickViews([CLOSED, view('brand_new', 'x=1'), ACTIVE])
    expect(got.map((v) => v.key)).toEqual(['closed', 'active'])
  })

  it('is empty before the counts arrive', () => {
    expect(knownQuickViews(undefined)).toEqual([])
  })
})

describe('quick view labels', () => {
  it('every key has an English fallback and a label in en and vi', () => {
    for (const key of QUICK_VIEW_KEYS) {
      expect(QUICK_VIEW_LABELS[key]).toBeTruthy()
      expect(en[`findings.quickView.${key}` as keyof typeof en]).toBe(QUICK_VIEW_LABELS[key])
      expect(vi[`findings.quickView.${key}` as keyof typeof vi]).toBeTruthy()
    }
  })
})
