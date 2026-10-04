/**
 * Typed pages (Websites, APIs, Mobile, Serverless) list one sub-type of a core
 * type. createAsset used to drop the sub-type, so an asset created on the
 * Websites page was stored as a bare `application` and never showed on the
 * page that created it (RFC-042 §6.3.8).
 */

import { describe, it, expect, vi, type Mock } from 'vitest'

vi.mock('@/lib/api/client', () => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  del: vi.fn(),
}))

import { post } from '@/lib/api/client'
import { createAsset } from '../use-assets'
import { ASSET_SUB_TYPES } from '@/features/asset-types/registry.generated'

const created = {
  id: 'a1',
  name: 'https://shop.example.com',
  type: 'application',
  sub_type: 'website',
  criticality: 'medium',
  status: 'active',
  scope: 'internal',
  exposure: 'unknown',
  risk_score: 0,
  finding_count: 0,
  created_at: '2026-10-03T00:00:00Z',
  updated_at: '2026-10-03T00:00:00Z',
}

describe('createAsset sub_type', () => {
  it('sends the sub-type of a typed page', async () => {
    ;(post as Mock).mockResolvedValueOnce(created)
    await createAsset({ name: 'https://shop.example.com', type: 'application', subType: 'website' })
    const body = (post as Mock).mock.calls[0][1] as Record<string, unknown>
    expect(body.type).toBe('application')
    expect(body.sub_type).toBe('website')
  })

  it('omits sub_type when the page has none', async () => {
    ;(post as Mock).mockResolvedValueOnce({ ...created, type: 'host', sub_type: undefined })
    await createAsset({ name: 'web-1', type: 'host' })
    const body = (post as Mock).mock.calls.at(-1)?.[1] as Record<string, unknown>
    expect(body.sub_type).toBeUndefined()
  })

  it('the typed pages use sub-types the registry declares', () => {
    expect(ASSET_SUB_TYPES.application).toEqual(
      expect.arrayContaining(['website', 'api', 'mobile_app'])
    )
    expect(ASSET_SUB_TYPES.host).toContain('serverless')
  })
})
