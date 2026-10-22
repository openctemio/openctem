import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { LoopViz } from '../loop-viz'
import { PathsViz } from '../paths-viz'
import type { PathsResult, StagesResult } from '../types'

const loop: StagesResult = {
  shape: 'stages',
  focus: 2,
  stages: [
    {
      key: 'scoping',
      label: 'Scoping',
      value: 9,
      state: 'good',
      drill: '/assets?is_crown_jewel=true',
      detail: { label_key: 'x.exposed', value: 2, drill: '/findings?asset_crown_jewel=true' },
    },
    {
      key: 'discovery',
      label: 'Discovery',
      value: null,
      unit: 'percent',
      state: 'unmeasured',
      reason_key: 'r.none',
    },
    {
      key: 'prioritize',
      label: 'Prioritize',
      value: 3,
      state: 'warn',
      drill: '/findings?state=open&priority_class=P0',
      flag_key: 'f.exploitable',
    },
    {
      key: 'validate',
      label: 'Validate',
      value: 40,
      unit: 'percent',
      state: 'warn',
      drill: '/validation',
    },
    {
      key: 'mobilize',
      label: 'Mobilize',
      value: 95,
      unit: 'percent',
      state: 'good',
      drill: '/findings?sla=x',
    },
  ],
}

describe('LoopViz', () => {
  it('is an ordered list of stages in loop order with the focus as the current step', () => {
    render(<LoopViz result={loop} />)
    const list = screen.getByRole('list', { name: 'Stages' })
    expect(list.tagName).toBe('OL')
    const items = within(list).getAllByRole('listitem')
    expect(items.map((li) => li.textContent?.slice(0, 8))).toEqual(
      expect.arrayContaining([expect.stringContaining('Scoping')])
    )
    expect(items).toHaveLength(5)
    expect(items[2]).toHaveAttribute('aria-current', 'step')
    expect(items.filter((li) => li.hasAttribute('aria-current'))).toHaveLength(1)
    // The current step says where to act, with the stage's own call to action.
    expect(within(items[2]).getByText('f.exploitable')).toBeInTheDocument()
  })

  it('every figure opens the list it counts, the second figure its own', () => {
    render(<LoopViz result={loop} />)
    expect(screen.getByRole('link', { name: 'Scoping: 9' })).toHaveAttribute(
      'href',
      '/assets?is_crown_jewel=true'
    )
    // An unknown message key falls back to the bare figure.
    expect(screen.getByRole('link', { name: '2' })).toHaveAttribute(
      'href',
      '/findings?asset_crown_jewel=true'
    )
    expect(screen.getByRole('link', { name: 'Prioritize: 3' })).toHaveAttribute(
      'href',
      '/findings?state=open&priority_class=P0'
    )
  })

  it('a stage without a denominator shows the reason and a dash, never 0', () => {
    render(<LoopViz result={loop} />)
    const discovery = screen.getByText('Discovery').closest('li')!
    expect(discovery).toHaveAttribute('data-state', 'unmeasured')
    expect(within(discovery).getByText('—')).toBeInTheDocument()
    expect(within(discovery).getByText('r.none')).toBeInTheDocument()
    expect(within(discovery).queryByText('0')).toBeNull()
  })

  it('states are words and icons on a neutral border, never a coloured stripe', () => {
    const { container } = render(<LoopViz result={loop} />)
    expect(screen.getAllByText('On track')).toHaveLength(2)
    expect(screen.getAllByText('Needs attention')).toHaveLength(2)
    for (const li of container.querySelectorAll('li')) {
      expect(li.className).not.toMatch(/border-(l|t|s)-|bg-(success|warning|destructive)/)
      for (const el of li.querySelectorAll('span')) {
        expect(el.className).not.toMatch(/\bh-1\b.*bg-|bg-(success|warning|destructive)\b/)
      }
    }
  })
})

const paths: PathsResult = {
  shape: 'paths',
  reachable: 2,
  designated: 5,
  rows: [
    {
      id: 'a1',
      name: 'payroll-db',
      reachable_from: 3,
      entry_point: false,
      score: 41.6,
      href: '/assets/a1',
    },
    { id: 'a2', name: 'vpn', reachable_from: 0, entry_point: true, score: 12, href: '/assets/a2' },
  ],
}

describe('PathsViz', () => {
  it('shows the reachable count linked to the attack paths and the top crown jewels', () => {
    render(<PathsViz result={paths} href="/attack-paths" />)
    expect(screen.getByRole('link', { name: '2 crown jewels reachable' })).toHaveAttribute(
      'href',
      '/attack-paths'
    )
    expect(screen.getByRole('link', { name: /payroll-db/ })).toHaveAttribute('href', '/assets/a1')
    expect(screen.getByText('from 3 entry points')).toBeInTheDocument()
    expect(screen.getByText('Entry point itself')).toBeInTheDocument()
  })

  it('none designated and none reachable are different empty states', () => {
    const { rerender } = render(
      <PathsViz result={{ ...paths, designated: 0, reachable: 0, rows: [] }} />
    )
    expect(screen.getByText('No crown jewels designated')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Designate crown jewels' })).toHaveAttribute(
      'href',
      '/crown-jewels'
    )
    rerender(<PathsViz result={{ ...paths, reachable: 0, rows: [] }} href="/attack-paths" />)
    expect(
      screen.getByText('No attack path reaches a crown jewel in your scope.')
    ).toBeInTheDocument()
  })
})
