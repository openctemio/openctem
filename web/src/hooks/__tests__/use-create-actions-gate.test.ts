import { describe, expect, it } from 'vitest'
import routePermissions from '@/config/api-route-permissions.json'
import { INVITE_GATE, INVITE_ROUTE_KEY } from '../use-create-actions'

describe('the invite gate kept beside the create actions', () => {
  it('matches the generated route table', () => {
    const generated = (routePermissions as Record<string, unknown>)[INVITE_ROUTE_KEY]
    expect(INVITE_GATE).toEqual(generated)
  })
})
