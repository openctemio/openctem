import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { RoleChecklist, selectableRoles, type RoleChecklistItem } from '../role-checklist'

// Only the owner may make someone an administrator (settings decision B2); the
// API refuses it from anyone else, so the picker does not offer it.

const roles: RoleChecklistItem[] = [
  {
    id: 'r-owner',
    slug: 'owner',
    name: 'Owner',
    description: '',
    is_system: true,
    permission_count: 1,
  },
  {
    id: 'r-admin',
    slug: 'admin',
    name: 'Administrator',
    description: '',
    is_system: true,
    permission_count: 1,
  },
  {
    id: 'r-member',
    slug: 'member',
    name: 'Member',
    description: '',
    is_system: true,
    permission_count: 1,
  },
  {
    id: 'r-custom',
    slug: 'admin',
    name: 'Custom admin-ish',
    description: '',
    is_system: false,
    permission_count: 1,
  },
]

describe('selectableRoles', () => {
  it('hides the owner role always and the admin role from non-owners', () => {
    expect(selectableRoles(roles).map((r) => r.id)).toEqual(['r-member', 'r-custom'])
  })

  it('offers the admin role to the owner', () => {
    expect(selectableRoles(roles, { canGrantAdmin: true }).map((r) => r.id)).toEqual([
      'r-admin',
      'r-member',
      'r-custom',
    ])
  })

  it('keeps the admin role when it is already selected', () => {
    expect(selectableRoles(roles, { keep: ['r-admin'] }).map((r) => r.id)).toContain('r-admin')
  })
})

describe('RoleChecklist', () => {
  it('does not show the administrator role to a non-owner', () => {
    render(<RoleChecklist roles={roles} selected={[]} onChange={() => {}} />)
    expect(screen.queryByLabelText('Administrator')).toBeNull()
    expect(screen.getByLabelText('Member')).toBeTruthy()
  })

  it('shows the administrator role to the owner', () => {
    render(<RoleChecklist roles={roles} selected={[]} onChange={() => {}} canGrantAdmin />)
    expect(screen.getByLabelText('Administrator')).toBeTruthy()
  })
})
