import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { DetailTabs } from '../detail-sheet-layout'

const TABS = ['overview', 'owners', 'timeline', 'relations', 'software', 'findings', 'details'].map(
  (v) => ({
    value: v,
    label: v[0].toUpperCase() + v.slice(1),
  })
)

// jsdom does no layout: give every label 80px and the strip 300px.
function fakeLayout(stripWidth: number) {
  vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockReturnValue(80)
  vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(stripWidth)
}

afterEach(() => vi.restoreAllMocks())

describe('DetailTabs overflow', () => {
  it('shows every tab when they fit', () => {
    fakeLayout(2000)
    render(<DetailTabs tabs={TABS} value="overview" onValueChange={() => {}} />)
    expect(screen.getAllByRole('tab')).toHaveLength(7)
    expect(screen.queryByRole('button', { name: /More/ })).not.toBeInTheDocument()
  })

  it('moves the tabs that do not fit under More, never cutting one off', async () => {
    fakeLayout(300)
    const onChange = vi.fn()
    render(<DetailTabs tabs={TABS} value="overview" onValueChange={onChange} />)
    // 300px: two 80px tabs + gap + "More" (80px) fit.
    expect(screen.getAllByRole('tab').map((t) => t.textContent)).toEqual(['Overview', 'Owners'])
    await userEvent.click(screen.getByRole('button', { name: /More/ }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Findings' }))
    expect(onChange).toHaveBeenCalledWith('findings')
  })

  it('keeps the active tab visible', () => {
    fakeLayout(300)
    render(<DetailTabs tabs={TABS} value="findings" onValueChange={() => {}} />)
    const shown = screen.getAllByRole('tab').map((t) => t.textContent)
    expect(shown).toEqual(['Overview', 'Findings'])
    expect(screen.getByRole('tab', { name: 'Findings' })).toHaveAttribute('data-state', 'active')
  })
})
