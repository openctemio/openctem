/**
 * Mutating controls follow the API's own route gates (generated map). These
 * pin the rows of the settings audit (23a B24) where a button used to pick a
 * different permission than the API checks, so the 403-after-click and the
 * hidden-but-allowed cases cannot come back.
 */
import { describe, expect, it } from 'vitest'
import { passesRouteGate, routeGate, type ApiRouteKey } from '../can-mutate'

const MEMBER_PERMS = [
  'settings:write',
  'pentest:write',
  'scans:secret_store:write',
  'scans:tenant_tools:write',
  'team:groups:write',
]

describe('route gates from the API route table', () => {
  const cases: Array<{
    key: ApiRouteKey
    perms: string[]
    role: string
    allowed: boolean
    why: string
  }> = [
    {
      key: 'PATCH /api/v1/tenants/{tenant}/settings/pentest',
      perms: MEMBER_PERMS,
      role: 'member',
      allowed: false,
      why: 'pentest settings are admin-only even with settings:write',
    },
    {
      key: 'PATCH /api/v1/tenants/{tenant}/settings/pentest',
      perms: ['settings:write'],
      role: 'admin',
      allowed: true,
      why: 'admins with settings:write may edit pentest settings',
    },
    {
      key: 'POST /api/v1/secret-store',
      perms: ['scans:secret_store:write'],
      role: 'member',
      allowed: true,
      why: 'source credentials need secret_store:write, not the leaked-credentials permission',
    },
    {
      key: 'PUT /api/v1/tools/{id}',
      perms: ['scans:tenant_tools:write'],
      role: 'member',
      allowed: false,
      why: 'custom tools need tools:write; tenant_tools:write only changes settings',
    },
    {
      key: 'PATCH /api/v1/tools/settings',
      perms: ['scans:tenant_tools:write'],
      role: 'member',
      allowed: true,
      why: 'switching tools on or off needs tenant_tools:write',
    },
    {
      key: 'POST /api/v1/integrations/{id}/test',
      perms: ['integrations:scm:write'],
      role: 'member',
      allowed: false,
      why: 'testing an integration needs integrations:manage',
    },
    {
      key: 'DELETE /api/v1/assignment-rules/{id}',
      perms: ['team:assignment_rules:delete'],
      role: 'admin',
      allowed: false,
      why: 'deleting an assignment rule is owner-only',
    },
    {
      key: 'POST /api/v1/tenants/{tenant}/invitations/{invitationId}/resend',
      perms: ['team:members:invite'],
      role: 'viewer',
      allowed: false,
      why: 'resending an invitation is admin-only',
    },
    {
      key: 'PATCH /api/v1/attachments/storage-config',
      perms: ['settings:write'],
      role: 'member',
      allowed: false,
      why: 'storage configuration is admin-only',
    },
  ]

  for (const c of cases) {
    it(`${c.key}: ${c.why}`, () => {
      expect(passesRouteGate(routeGate(c.key), c.perms, c.role)).toBe(c.allowed)
    })
  }

  it('an unknown role never passes a role gate', () => {
    expect(passesRouteGate({ min_role: 'admin' }, ['settings:write'], undefined)).toBe(false)
  })

  it('any_of groups need one permission from each group', () => {
    const gate = { any_of: [['a', 'b'], ['c']] }
    expect(passesRouteGate(gate, ['b', 'c'], 'member')).toBe(true)
    expect(passesRouteGate(gate, ['a'], 'member')).toBe(false)
  })
})
