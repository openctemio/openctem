import { describe, expect, it, vi } from 'vitest'

vi.mock('next/navigation', () => ({
  useSearchParams: () => null,
  useRouter: () => ({ push: vi.fn() }),
}))

import { presetFromParams } from '../components/mapping-list-view'

const ok = 'new=1&integration=0193e7a2-1111-7222-8333-944455556666&kind=task&project=sec&type=10043'

describe('mapping preset from a link', () => {
  it('opens the create dialog for a well-formed destination', () => {
    expect(presetFromParams(new URLSearchParams(ok))).toEqual({
      integrationId: '0193e7a2-1111-7222-8333-944455556666',
      kind: 'task',
      projectKey: 'SEC',
      issueTypeId: '10043',
    })
  })

  it('ignores anything malformed', () => {
    for (const bad of [
      ok.replace('new=1', 'new=0'),
      ok.replace('kind=task', 'kind=epic'),
      ok.replace('type=10043', 'type=10043%3Cscript%3E'),
      ok.replace('project=sec', 'project=SEC%2F..'),
      ok.replace('0193e7a2-1111-7222-8333-944455556666', 'x'),
    ]) {
      expect(presetFromParams(new URLSearchParams(bad))).toBeUndefined()
    }
    expect(presetFromParams(null)).toBeUndefined()
  })
})
