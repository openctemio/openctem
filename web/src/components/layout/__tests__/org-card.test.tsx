import { describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { OrgCard, type OrgCardOrganization } from '../org-card'

const CURRENT = { id: 'o1', name: 'Home Co', role: 'owner' }

function renderCard(organizations: OrgCardOrganization[], onSwitch = vi.fn()) {
  render(
    <OrgCard
      current={CURRENT}
      organizations={organizations}
      canCreate={false}
      isSwitching={false}
      onSwitch={onSwitch}
      onCreate={vi.fn()}
      onNavigate={vi.fn()}
    />
  )
  return onSwitch
}

const rows = () => screen.getAllByTestId('org-card-switch-item')

describe('OrgCard organization list (external members)', () => {
  it('marks an organization where the user is external and says when access ends', () => {
    renderCard([
      { id: 'o1', name: 'Home Co', role: 'owner' },
      {
        id: 'o2',
        name: 'Sister Co',
        role: 'viewer',
        external: true,
        accessExpiresAt: '2027-01-05T00:00:00Z',
      },
    ])
    const sister = rows()[1]
    expect(within(sister).getByTestId('org-card-external')).toHaveTextContent('External')
    expect(within(sister).getByTestId('org-card-row-note')).toHaveTextContent(
      /Access ends Jan 5, 2027/
    )
    expect(within(rows()[0]).queryByTestId('org-card-external')).toBeNull()
  })

  it('disables a blocked organization and says why', async () => {
    const onSwitch = renderCard([
      { id: 'o1', name: 'Home Co' },
      { id: 'o2', name: 'Expired Co', external: true, blockedReason: 'expired' },
      { id: 'o3', name: 'Open Co' },
    ])
    const blocked = rows()[1]
    expect(blocked).toBeDisabled()
    expect(blocked).toHaveAttribute('data-blocked', 'true')
    expect(within(blocked).getByTestId('org-card-row-note')).toHaveTextContent('Your access ended')
    await userEvent.setup().click(rows()[2])
    expect(onSwitch).toHaveBeenCalledWith('o3')
    expect(onSwitch).not.toHaveBeenCalledWith('o2')
  })

  it('offers a search above seven organizations', async () => {
    const many = Array.from({ length: 9 }, (_, i) => ({ id: `o${i + 1}`, name: `Org ${i + 1}` }))
    many[4] = { id: 'o5', name: 'Acme Partner' }
    renderCard(many)
    await userEvent.setup().type(screen.getByTestId('org-card-search'), 'acme')
    expect(rows()).toHaveLength(1)
    expect(rows()[0]).toHaveTextContent('Acme Partner')
  })

  it('has no search with a few organizations', () => {
    renderCard([
      { id: 'o1', name: 'Home Co' },
      { id: 'o2', name: 'Other' },
    ])
    expect(screen.queryByTestId('org-card-search')).toBeNull()
  })
})
