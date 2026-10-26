import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { TeamAccessFields, isElevatedChoice, type TeamAccessValue } from '../team-access-fields'
import type { TeamPresetTemplate } from '../../types'

const templates: TeamPresetTemplate[] = [
  {
    id: 'security-analyst',
    version: 3,
    name: 'Security analyst',
    description: 'Triages findings.',
    personas: [],
    has_full_data_access: false,
  },
  {
    id: 'auditor',
    version: 1,
    name: 'Auditor',
    description: 'Reads everything.',
    personas: [],
    has_full_data_access: true,
  },
]

function setup(value: TeamAccessValue, canSetAllAssets: boolean) {
  const onChange = vi.fn()
  render(
    <TeamAccessFields
      idPrefix="t"
      templates={templates}
      value={value}
      onChange={onChange}
      canSetAllAssets={canSetAllAssets}
    />
  )
  return onChange
}

describe('TeamAccessFields', () => {
  it('lists the presets with their descriptions and toggles one', async () => {
    const user = userEvent.setup()
    const onChange = setup({ presets: [], scopeMode: 'specific' }, true)
    expect(screen.getByText('Triages findings.')).toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: /Security analyst/ }))
    expect(onChange).toHaveBeenCalledWith({ presets: ['security-analyst'], scopeMode: 'specific' })
  })

  it('offers All assets to owners only', () => {
    setup({ presets: [], scopeMode: 'specific' }, false)
    expect(screen.getByRole('radio', { name: /All assets/ })).toBeDisabled()
    expect(screen.getByText(/Only an owner can choose this/)).toBeInTheDocument()
  })

  it('lets an owner choose All assets and marks the team elevated', async () => {
    const user = userEvent.setup()
    const onChange = setup({ presets: [], scopeMode: 'specific' }, true)
    await user.click(screen.getByRole('radio', { name: /All assets/ }))
    expect(onChange).toHaveBeenCalledWith({ presets: [], scopeMode: 'all_assets' })
  })

  it('shows the elevated note for a preset that sees all assets', () => {
    setup({ presets: ['auditor'], scopeMode: 'specific' }, true)
    expect(screen.getByRole('note')).toHaveTextContent('elevated access')
  })

  it('knows when a choice is elevated', () => {
    expect(
      isElevatedChoice({ presets: ['security-analyst'], scopeMode: 'specific' }, templates)
    ).toBe(false)
    expect(isElevatedChoice({ presets: ['auditor'], scopeMode: 'specific' }, templates)).toBe(true)
    expect(isElevatedChoice({ presets: [], scopeMode: 'all_assets' }, templates)).toBe(true)
  })
})
