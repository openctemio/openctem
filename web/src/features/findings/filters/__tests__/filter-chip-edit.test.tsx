import { useState } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FilterBar } from '../filter-bar'
import { withOwnedFields } from '../contract'
import {
  withFilter,
  withFilterReplaced,
  withoutParam,
  type FieldContract,
  type FilterContract,
} from '../model'

vi.mock('@/features/findings/components/assignee-select', () => ({
  AssigneeSelect: () => null,
}))

// The hook the kit's ResponsivePopover reads: phone-sized below 768 px.
const mobile = vi.hoisted(() => ({ value: false }))
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => mobile.value }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= () => {}

/** What the API describes to the viewer (the page's own list of fields has no values). */
const contract: FilterContract = {
  fields: [
    { name: 'severity', type: 'enum', ops: ['in', 'not_in'], enum: ['critical', 'high', 'low'] },
    { name: 'epss_score', type: 'number', ops: ['gte', 'gt', 'lte', 'lt'] },
    { name: 'is_in_kev', type: 'boolean', ops: ['eq'] },
    { name: 'branch_id', type: 'id', ops: ['in'] },
  ],
}
const f = (n: string) => contract.fields.find((x) => x.name === n) as FieldContract
const sorted = (q: URLSearchParams) => [...q.entries()].sort().join('&')

function bar(search: string, over: Partial<React.ComponentProps<typeof FilterBar>> = {}) {
  const onSearchChange = vi.fn()
  const onOpenChange = vi.fn()
  render(
    <FilterBar
      search={new URLSearchParams(search)}
      contract={withOwnedFields(contract)}
      skip={new Set()}
      onSearchChange={onSearchChange}
      edit={{ contract, contractFailed: false, onOpenChange }}
      {...over}
    />
  )
  return { onSearchChange, onOpenChange }
}

const editButton = (text: string) => screen.getByRole('button', { name: `Edit filter ${text}` })

beforeEach(() => {
  mobile.value = false
})

describe('editing a filter from its chip', () => {
  it('opens the field editor on the chip operator and values, and asks for the contract', async () => {
    const { onOpenChange } = bar('severity=critical,high')
    await userEvent.click(editButton('Severity: Critical, High'))
    expect(onOpenChange).toHaveBeenCalledWith(true)
    const editor = await screen.findByRole('dialog', { name: 'Edit Severity filter' })
    expect(within(editor).getByRole('combobox', { name: 'Condition' })).toHaveTextContent(/^is$/)
    expect(within(editor).getByRole('checkbox', { name: 'Critical' })).toBeChecked()
    expect(within(editor).getByRole('checkbox', { name: 'High' })).toBeChecked()
    expect(within(editor).getByRole('checkbox', { name: 'Low' })).not.toBeChecked()
    // One filter is edited: there is no way back to the list of fields.
    expect(within(editor).queryByRole('button', { name: 'Back to fields' })).toBeNull()
  })

  it('"is" to "is not" keeps the values and writes what Add filter would, in the chip place', async () => {
    const search = 'q=x&severity=critical,high&epss_score_gte=0.5&page=3'
    const { onSearchChange } = bar(search)
    await userEvent.click(editButton('Severity: Critical, High'))
    await userEvent.click(screen.getByRole('combobox', { name: 'Condition' }))
    await userEvent.click(screen.getByRole('option', { name: 'is not' }))
    expect(screen.getByRole('checkbox', { name: 'Critical' })).toBeChecked()
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    expect(onSearchChange).toHaveBeenCalledOnce()
    const next = onSearchChange.mock.calls[0][0] as URLSearchParams
    expect(next.toString()).toBe('q=x&severity_not=critical%2Chigh&epss_score_gte=0.5')
    const viaAddFilter = withFilter(
      withoutParam(new URLSearchParams(search), 'severity'),
      f('severity'),
      'not_in',
      ['critical', 'high']
    )
    expect(sorted(next)).toBe(sorted(viaAddFilter))
  })

  it('a number opens on its operator and value; another comparison keeps the value', async () => {
    const { onSearchChange } = bar('epss_score_gte=0.5')
    await userEvent.click(editButton('EPSS score ≥ 0.5'))
    expect(screen.getByRole('combobox', { name: 'Condition' })).toHaveTextContent('≥')
    expect(screen.getByLabelText('Value')).toHaveValue('0.5')
    await userEvent.click(screen.getByRole('combobox', { name: 'Condition' }))
    await userEvent.click(screen.getByRole('option', { name: '≤' }))
    expect(screen.getByLabelText('Value')).toHaveValue('0.5')
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    expect((onSearchChange.mock.calls[0][0] as URLSearchParams).toString()).toBe(
      'epss_score_lte=0.5'
    )
  })

  it('new values on the same operator replace the old ones', async () => {
    const { onSearchChange } = bar('severity=critical')
    await userEvent.click(editButton('Severity: Critical'))
    await userEvent.click(screen.getByRole('checkbox', { name: 'Low' }))
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    expect((onSearchChange.mock.calls[0][0] as URLSearchParams).toString()).toBe(
      'severity=critical%2Clow'
    )
  })

  it('a yes / no filter marks its current answer', async () => {
    const { onSearchChange } = bar('is_in_kev=true')
    await userEvent.click(screen.getByRole('button', { name: /^Edit filter/ }))
    expect(screen.getByRole('button', { name: 'Yes' })).toHaveAttribute('aria-pressed', 'true')
    await userEvent.click(screen.getByRole('button', { name: 'No' }))
    expect((onSearchChange.mock.calls[0][0] as URLSearchParams).toString()).toBe('is_in_kev=false')
  })

  it('Escape changes nothing and returns focus to the chip', async () => {
    const { onSearchChange, onOpenChange } = bar('severity=critical')
    const chip = editButton('Severity: Critical')
    await userEvent.click(chip)
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Low' }))
    await userEvent.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(onSearchChange).not.toHaveBeenCalled()
    expect(onOpenChange).toHaveBeenLastCalledWith(false)
    expect(chip).toHaveFocus()
  })

  it('the chip text is a button the keyboard opens', async () => {
    bar('severity=critical')
    editButton('Severity: Critical').focus()
    await userEvent.keyboard('{Enter}')
    expect(await screen.findByRole('dialog', { name: 'Edit Severity filter' })).toBeInTheDocument()
  })

  it('after an operator change focus is on the new chip', async () => {
    function Page() {
      const [search, setSearch] = useState(new URLSearchParams('severity=critical'))
      return (
        <FilterBar
          search={search}
          contract={withOwnedFields(contract)}
          skip={new Set()}
          onSearchChange={setSearch}
          edit={{ contract, contractFailed: false }}
        />
      )
    }
    render(<Page />)
    await userEvent.click(editButton('Severity: Critical'))
    await userEvent.click(screen.getByRole('combobox', { name: 'Condition' }))
    await userEvent.click(screen.getByRole('option', { name: 'is not' }))
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(editButton('Severity is not Critical')).toHaveFocus())
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('says it is loading until the contract is there, and when it could not be loaded', async () => {
    bar('severity=critical', { edit: { contract: undefined, contractFailed: false } })
    await userEvent.click(editButton('Severity: Critical'))
    expect(await screen.findByRole('status')).toHaveTextContent('Loading filters…')
    expect(screen.queryByRole('button', { name: 'Apply' })).toBeNull()
  })

  it('reports a contract that could not be loaded', async () => {
    bar('severity=critical', { edit: { contract: undefined, contractFailed: true } })
    await userEvent.click(editButton('Severity: Critical'))
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be loaded')
  })

  it('a chip of the open saved view keeps its lock and is not editable', () => {
    bar('epss_score_gte=0.5', {
      viewFilter: { v: 1, filter: { all: [{ field: 'severity', op: 'in', value: ['critical'] }] } },
    })
    const locked = screen
      .getAllByTestId('filter-chip')
      .filter((c) => c.getAttribute('data-locked') === 'true')
    expect(locked).toHaveLength(1)
    expect(within(locked[0]).queryByRole('button')).toBeNull()
    expect(within(locked[0]).getByRole('img', { name: /from the saved view/i })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /^Edit filter/ })).toHaveLength(1)
  })

  it('an unknown filter and a field Add filter does not offer are not editable', () => {
    bar('sevrity=high&branch_id=11111111-1111-4111-8111-111111111111')
    expect(screen.getByTestId('filter-chip-unknown')).toBeInTheDocument()
    expect(screen.getAllByTestId('filter-chip')).toHaveLength(1)
    expect(screen.queryByRole('button', { name: /^Edit filter/ })).toBeNull()
  })

  it('without the edit seam a chip is text only', () => {
    bar('severity=critical', { edit: undefined })
    expect(screen.queryByRole('button', { name: /^Edit filter/ })).toBeNull()
    expect(screen.getByText('Severity: Critical')).toBeInTheDocument()
  })

  it('below 768 px the editor is a bottom sheet titled by the filter', async () => {
    mobile.value = true
    bar('severity=critical')
    await userEvent.click(editButton('Severity: Critical'))
    const sheet = await screen.findByRole('dialog', { name: 'Edit Severity filter' })
    expect(sheet).toHaveAttribute('data-slot', 'responsive-popover-sheet')
    expect(within(sheet).getByRole('checkbox', { name: 'Critical' })).toBeChecked()
  })
})

describe('withFilterReplaced', () => {
  it('rewrites the filter where it was and resets the page', () => {
    const next = withFilterReplaced(
      new URLSearchParams('a=1&severity=critical&b=2&page=4'),
      'severity',
      f('severity'),
      'not_in',
      ['critical', 'high']
    )
    expect(next.toString()).toBe('a=1&severity_not=critical%2Chigh&b=2')
  })

  it('replaces a filter the new operator shares its param with', () => {
    const next = withFilterReplaced(
      new URLSearchParams('severity_not=low&severity=critical'),
      'severity',
      f('severity'),
      'not_in',
      ['critical']
    )
    expect(next.toString()).toBe('severity_not=critical')
  })

  it('leaves the URL alone for an operator the field does not have', () => {
    const next = withFilterReplaced(
      new URLSearchParams('severity=critical'),
      'severity',
      f('severity'),
      'gte',
      ['1']
    )
    expect(next.toString()).toBe('severity=critical')
  })

  it('no value left removes the filter', () => {
    const next = withFilterReplaced(
      new URLSearchParams('severity=critical&q=x'),
      'severity',
      f('severity'),
      'in',
      [' ']
    )
    expect(next.toString()).toBe('q=x')
  })
})
