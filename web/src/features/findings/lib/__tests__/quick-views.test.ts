import { describe, expect, it } from 'vitest'
import {
  QUICK_VIEW_KEYS,
  QUICK_VIEW_LABELS,
  defaultHidesInformational,
  informationalHidden,
  knownQuickViews,
  quickViewHref,
  quickViewIsActive,
  withInformational,
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
    [
      'a column choice does not change the view',
      'status=new&state=all&columns=asset,status',
      TRIAGE,
      true,
    ],
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

describe('informational findings in the work views', () => {
  // What the API sends when the caller leaves them out (the default).
  const ACTIVE_HIDDEN = view('active', 'state=open&informational=false')
  const TRIAGE_HIDDEN = view('needs_triage', 'status=new&informational=false')

  it('follows the API rule when the URL does not say', () => {
    expect(defaultHidesInformational('', false)).toBe(true)
    expect(defaultHidesInformational('', true)).toBe(false)
    expect(defaultHidesInformational('state=open&related_to=me', false)).toBe(true)
    // Needs triage leaves them out whatever the preference.
    expect(defaultHidesInformational('status=new&state=all', true)).toBe(true)
    // Other lenses, an explicit severity and a saved view never hide them.
    expect(defaultHidesInformational('state=closed', false)).toBe(false)
    expect(defaultHidesInformational('state=all', false)).toBe(false)
    expect(defaultHidesInformational('severity=info', false)).toBe(false)
    expect(defaultHidesInformational('view=abc', false)).toBe(false)
  })

  it('reads an explicit choice first, but a severity pick always shows them', () => {
    expect(informationalHidden('informational=true', false)).toBe(false)
    expect(informationalHidden('state=all&informational=false', false)).toBe(true)
    expect(informationalHidden('severity=info&informational=false', false)).toBe(false)
  })

  it('keeps the param only where it differs from the default', () => {
    expect(withInformational(new URLSearchParams('state=open'), true, false).toString()).toBe(
      'state=open'
    )
    expect(withInformational(new URLSearchParams('state=open'), false, false).toString()).toBe(
      'state=open&informational=true'
    )
    expect(
      withInformational(
        new URLSearchParams('state=open&informational=true'),
        true,
        false
      ).toString()
    ).toBe('state=open')
    expect(withInformational(new URLSearchParams('state=all'), true, false).toString()).toBe(
      'state=all&informational=false'
    )
  })

  it('links the plain view and still matches the plain list', () => {
    expect(quickViewHref(ACTIVE_HIDDEN.params)).toBe('/findings?state=open')
    expect(quickViewHref(TRIAGE_HIDDEN.params, true)).toBe('/findings?status=new&state=all')
    expect(quickViewIsActive('', ACTIVE_HIDDEN)).toBe(true)
    expect(quickViewIsActive('status=new&state=all', TRIAGE_HIDDEN, true)).toBe(true)
  })

  it('a list showing them is not the view that hides them, and the reverse', () => {
    expect(quickViewIsActive('informational=true', ACTIVE_HIDDEN)).toBe(false)
    // A member who includes them: the API sends plain params.
    expect(quickViewIsActive('', ACTIVE, true)).toBe(true)
    expect(quickViewIsActive('informational=false', ACTIVE, true)).toBe(false)
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
