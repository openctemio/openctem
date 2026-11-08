import { describe, expect, it } from 'vitest'
import { defaultT } from '@/features/assets/lib/default-t'
import { ApiClientError } from '@/lib/api/error-handler'
import { LEAD_TYPE_IDS, LEAD_TYPE_REASONS, leadTypeKey } from '../lead-types.generated'
import en from '@/lib/i18n/dictionaries/en/exploration.json'
import vi from '@/lib/i18n/dictionaries/vi/exploration.json'
import {
  approvableIds,
  askErrorMessage,
  blockedReasonLabel,
  bulkOutcome,
  canApproveLead,
  canDismissLead,
  explorationHref,
  groupLinks,
  isLeadGroup,
  leadQuestion,
  leadStatusText,
  leadsUrl,
  linkHref,
  reasonLabel,
  scoreShare,
  statusSentence,
  tierKey,
  type Lead,
  type LeadSummary,
} from '../leads'

const t = defaultT

function lead(over: Partial<Lead> = {}): Lead {
  return {
    id: 'l1',
    type: 'dns.takeover_check',
    state: 'open',
    capability: 'check.takeover',
    tier: 1,
    subject_asset_id: '11111111-1111-4111-8111-111111111111',
    reason_code: 'cname_dangling',
    rationale: '',
    origin: 'rule',
    likelihood: 'medium',
    score: 1,
    attempts: 0,
    created_at: '2026-11-01T00:00:00Z',
    updated_at: '2026-11-02T00:00:00Z',
    ...over,
  }
}

const summary: LeadSummary = {
  open: 14,
  awaiting_approval: 3,
  running: 0,
  blocked: 0,
  done_30d: 0,
  proven_30d: 0,
  refuted_30d: 0,
  dispatches_30d: 0,
  last_step_at: '2026-11-08T10:00:00Z',
  scope: 'organization',
}

describe('lead type catalog in both languages', () => {
  it.each(LEAD_TYPE_IDS)('%s has a title and a question in en and vi', (id) => {
    for (const cat of [en, vi] as Record<string, string>[]) {
      expect(cat[`exploration.leadTypes.${leadTypeKey(id)}.title`]).toBeTruthy()
      expect(cat[`exploration.leadTypes.${leadTypeKey(id)}.question`]).toBeTruthy()
      for (const r of LEAD_TYPE_REASONS[id]) expect(cat[`exploration.reasons.${r}`]).toBeTruthy()
    }
  })

  it('reads the question in plain words, and an unknown type as given', () => {
    expect(leadQuestion(t, 'dns.takeover_check')).toMatch(/claimed/)
    expect(leadQuestion(t, 'x.unknown')).toBe('x.unknown')
    expect(reasonLabel(t, 'new_code')).toBe('new_code')
  })
})

describe('status sentence', () => {
  const rel = () => '5 minutes ago'
  it('says next steps, waiting and the last step', () => {
    expect(statusSentence(t, summary, rel)).toBe(
      '14 next steps, 3 waiting for your approval, last step 5 minutes ago'
    )
  })
  it('leaves out what is zero and says when nothing ran yet', () => {
    expect(
      statusSentence(
        t,
        { ...summary, open: 1, awaiting_approval: 0, running: 2, last_step_at: undefined },
        rel
      )
    ).toBe('1 next step, 2 running, no step taken yet')
  })
})

describe('labels', () => {
  it('names known blocked reasons and shows an unknown code as given', () => {
    expect(blockedReasonLabel(t, 'out_of_scope')).toBe('Out of scope')
    expect(blockedReasonLabel(t, 'SCOPE_NO_ENTRY')).toBe('Refused by a check (SCOPE_NO_ENTRY)')
    expect(blockedReasonLabel(t, undefined)).toBe('')
  })

  it('maps tiers', () => {
    expect(tierKey(0)).toBe('passive')
    expect(tierKey(1)).toBe('active')
    expect(tierKey(2)).toBe('intrusive')
  })

  it('states a lead the way the asset card says it', () => {
    const day = () => '3 Nov 2026'
    expect(leadStatusText(t, lead({ state: 'awaiting_approval' }), day)).toBe(
      'Waiting for approval'
    )
    expect(leadStatusText(t, lead({ state: 'open' }), day)).toBe('Scheduled')
    expect(leadStatusText(t, lead({ state: 'running' }), day)).toBe('Running')
    expect(leadStatusText(t, lead({ state: 'blocked', blocked_reason: 'excluded' }), day)).toBe(
      'Blocked: Excluded by a scope exclusion'
    )
    expect(
      leadStatusText(t, lead({ state: 'refuted', closed_at: '2026-11-03T00:00:00Z' }), day)
    ).toBe('Done: nothing found, 3 Nov 2026')
  })
})

describe('requests and links', () => {
  it('builds list URLs', () => {
    expect(leadsUrl({ group: 'waiting' })).toBe('/api/v1/exploration/leads?group=waiting')
    expect(leadsUrl({ assetId: 'a b', limit: 3 })).toBe(
      '/api/v1/exploration/leads?asset_id=a+b&limit=3'
    )
    expect(leadsUrl({ group: 'done', before: '2026-11-01T00:00:00Z' })).toContain('before=')
    expect(explorationHref('a1')).toBe('/exploration?asset=a1')
    expect(isLeadGroup('next')).toBe(true)
    expect(isLeadGroup('all')).toBe(false)
  })

  it('groups links in reading order and links only routable ends', () => {
    const groups = groupLinks([
      { rel: 'yields', end_kind: 'finding', end_id: 'f1', created_at: '' },
      { rel: 'derived_from', end_kind: 'asset', end_id: 'not-a-uuid', created_at: '' },
      { rel: 'dispatched_as', end_kind: 'scan_run', end_id: 'r1', created_at: '' },
    ])
    expect(groups.map(([rel]) => rel)).toEqual(['derived_from', 'dispatched_as', 'yields'])
    expect(linkHref(groups[0][1][0])).toBeUndefined()
    expect(linkHref(groups[1][1][0])).toBe('/scans/runs?run=r1')
    expect(linkHref(groups[2][1][0])).toBe('/findings/f1')
    expect(linkHref({ rel: 'derived_from', end_kind: 'lead', end_id: 'l2', created_at: '' })).toBe(
      undefined
    )
  })
})

describe('selection and results', () => {
  it('approves only leads still waiting', () => {
    const leads = [
      lead({ id: 'a', state: 'awaiting_approval' }),
      lead({ id: 'b', state: 'blocked' }),
      lead({ id: 'c', state: 'proposed' }),
    ]
    expect(approvableIds(leads, new Set(['a', 'b', 'c']))).toEqual(['a', 'c'])
    expect(canApproveLead(leads[1])).toBe(false)
    expect(canDismissLead(leads[1])).toBe(true)
    expect(canDismissLead(lead({ state: 'refuted' }))).toBe(false)
  })

  it('counts a bulk answer', () => {
    expect(
      bulkOutcome([
        { id: 'a', ok: true },
        { id: 'b', ok: false, error: 'changed' },
      ])
    ).toEqual({ ok: 1, failed: 1 })
    expect(bulkOutcome(null)).toEqual({ ok: 0, failed: 0 })
  })

  it('scales the score bar to the highest score shown', () => {
    expect(scoreShare(2, 4)).toBe(0.5)
    expect(scoreShare(5, 4)).toBe(1)
    expect(scoreShare(1, 0)).toBe(0)
  })

  it('names the fix when asking fails', () => {
    expect(askErrorMessage(t, new ApiClientError('bad', 'BAD_REQUEST', 400))).toMatch(
      /does not apply/
    )
    expect(askErrorMessage(t, new ApiClientError('c', 'CONFLICT', 409))).toMatch(/already open/)
    expect(askErrorMessage(t, new Error('x'))).toMatch(/Try again/)
  })
})
