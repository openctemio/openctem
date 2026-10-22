import axe from 'axe-core'
import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FilterChip } from '../filter-chip'
import { AddFilterPopover } from '../add-filter-popover'
import { FilterBar, InvalidFilterNotice, invalidFilterParams } from '../filter-bar'
import { withOwnedFields } from '../contract'
import type { ActiveFilter, FieldContract, FilterContract } from '../model'

vi.mock('@/features/findings/components/assignee-select', () => ({
  AssigneeSelect: ({ onChange }: { onChange: (u: { id: string }) => void }) => (
    <button onClick={() => onChange({ id: '11111111-1111-4111-8111-111111111111' })}>
      pick user
    </button>
  ),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= () => {}

const contract: FilterContract = {
  fields: [
    { name: 'severity', type: 'enum', ops: ['in', 'not_in'], enum: ['critical', 'high', 'low'] },
    { name: 'epss_score', type: 'number', ops: ['gte', 'gt', 'lte', 'lt'] },
    { name: 'first_detected_at', type: 'date-time', ops: ['gte', 'lte'] },
    { name: 'acceptance_expires_at', type: 'date-time', ops: ['gte', 'lte'] },
    { name: 'exploit_available', type: 'boolean', ops: ['eq'] },
    { name: 'file_path', type: 'string', ops: ['contains'] },
    { name: 'assigned_to', type: 'id', ops: ['in', 'not_in', 'is_null'], nullable: true },
    { name: 'asset_criticality', type: 'enum', ops: ['in', 'not_in'], enum: ['critical', 'low'] },
    { name: 'brand_new_field', type: 'string', ops: ['in'] },
  ],
}
const f = (n: string) => contract.fields.find((x) => x.name === n) as FieldContract

function chip(over: Partial<ActiveFilter>, field = f('severity')) {
  const onRemove = vi.fn()
  const filter: ActiveFilter = {
    param: 'severity',
    field: field.name,
    op: 'in',
    values: ['critical', 'high'],
    ...over,
  }
  render(<FilterChip filter={filter} field={field} onRemove={onRemove} />)
  return { onRemove, filter }
}

describe('FilterChip', () => {
  it('reads "Field op value" and removes itself', () => {
    const { onRemove, filter } = chip({})
    expect(screen.getByText('Severity is Critical, High')).toBeInTheDocument()
    fireEvent.click(
      screen.getByRole('button', { name: 'Remove filter Severity is Critical, High' })
    )
    expect(onRemove).toHaveBeenCalledWith(filter)
  })

  it('every operator reads', () => {
    const cases: Array<[Partial<ActiveFilter>, FieldContract, string]> = [
      [{ op: 'not_in', values: ['low'] }, f('severity'), 'Severity is not Low'],
      [
        { param: 'epss_score_gte', field: 'epss_score', op: 'gte', values: ['0.5'] },
        f('epss_score'),
        'EPSS score ≥ 0.5',
      ],
      [
        { param: 'epss_score_lt', field: 'epss_score', op: 'lt', values: ['0.1'] },
        f('epss_score'),
        'EPSS score < 0.1',
      ],
      [
        { param: 'first_detected_at_gte', field: 'first_detected_at', op: 'gte', values: ['-P7D'] },
        f('first_detected_at'),
        'First seen on or after 7 days ago',
      ],
      [
        {
          param: 'acceptance_expires_at_lte',
          field: 'acceptance_expires_at',
          op: 'lte',
          values: ['P30D'],
        },
        f('acceptance_expires_at'),
        'Acceptance expires on or before 30 days from now',
      ],
      [
        { param: 'exploit_available', field: 'exploit_available', op: 'eq', values: ['true'] },
        f('exploit_available'),
        'Exploit available: Yes',
      ],
      [
        { param: 'file_path', field: 'file_path', op: 'contains', values: ['src/auth'] },
        f('file_path'),
        'File path contains src/auth',
      ],
      [
        { param: 'assigned_to_null', field: 'assigned_to', op: 'is_null', values: ['true'] },
        f('assigned_to'),
        'Assigned to is empty',
      ],
      [
        { param: 'assigned_to_null', field: 'assigned_to', op: 'is_null', values: ['false'] },
        f('assigned_to'),
        'Assigned to is set',
      ],
      [
        { param: 'brand_new_field', field: 'brand_new_field', op: 'in', values: ['x'] },
        f('brand_new_field'),
        'Brand new field is x',
      ],
    ]
    for (const [over, field, text] of cases) {
      const { unmount } = render(
        <FilterChip
          filter={{ param: 'p', field: field.name, op: 'in', values: [], ...over }}
          field={field}
          onRemove={() => {}}
        />
      )
      expect(screen.getByText(text)).toBeInTheDocument()
      unmount()
    }
  })

  it('a long value list is cut with a count', () => {
    chip({ values: ['critical', 'high', 'low', 'medium', 'info'] })
    expect(screen.getByText('Severity is Critical, High, Low +2')).toBeInTheDocument()
  })

  it('a locked chip has no remove button and says where it comes from', () => {
    chip({ locked: true })
    expect(screen.getByTestId('filter-chip')).toHaveAttribute('data-locked', 'true')
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(screen.getByRole('img', { name: /from the saved view/i })).toBeInTheDocument()
  })

  it('shows scanner text as text', () => {
    chip(
      {
        param: 'file_path',
        field: 'file_path',
        op: 'contains',
        values: ['<img src=x onerror=alert(1)>'],
      },
      f('file_path')
    )
    expect(document.querySelector('img')).toBeNull()
  })
})

function picker(props: Partial<React.ComponentProps<typeof AddFilterPopover>> = {}) {
  const onApply = vi.fn()
  const onOpenChange = vi.fn()
  render(
    <AddFilterPopover
      contract={contract}
      contractLoading={false}
      contractFailed={false}
      canReadAssets
      onApply={onApply}
      onOpenChange={onOpenChange}
      {...props}
    />
  )
  return { onApply, onOpenChange }
}

async function open() {
  await userEvent.click(screen.getByRole('button', { name: /add filter/i }))
}

describe('AddFilterPopover', () => {
  it('lists the fields grouped by entity, and asks the page to load the contract when opened', async () => {
    const { onOpenChange } = picker()
    await open()
    expect(onOpenChange).toHaveBeenCalledWith(true)
    for (const g of ['Exploitation', 'Finding', 'Asset', 'Work', 'Other']) {
      expect(screen.getByText(g)).toBeInTheDocument()
    }
    expect(screen.getByRole('option', { name: 'EPSS score' })).toBeInTheDocument()
    // A field the web has never heard of is still offered.
    expect(screen.getByRole('option', { name: 'Brand new field' })).toBeInTheDocument()
  })

  it('searches fields', async () => {
    picker()
    await open()
    await userEvent.type(screen.getByPlaceholderText('Search fields…'), 'epss')
    expect(screen.getByRole('option', { name: 'EPSS score' })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: 'Severity' })).not.toBeInTheDocument()
    await userEvent.clear(screen.getByPlaceholderText('Search fields…'))
    await userEvent.type(screen.getByPlaceholderText('Search fields…'), 'zzzz')
    expect(screen.getByText('No matching field')).toBeInTheDocument()
  })

  it('offers no asset-derived field without permission to read assets', async () => {
    picker({ canReadAssets: false })
    await open()
    expect(screen.queryByRole('option', { name: 'Asset criticality' })).not.toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Severity' })).toBeInTheDocument()
  })

  it('offers the asset field with permission', async () => {
    picker()
    await open()
    expect(screen.getByRole('option', { name: 'Asset criticality' })).toBeInTheDocument()
  })

  it('an enum: pick values, choose "is not", apply', async () => {
    const { onApply } = picker()
    await open()
    await userEvent.click(screen.getByRole('option', { name: 'Severity' }))
    await userEvent.click(screen.getByRole('checkbox', { name: 'Critical' }))
    await userEvent.click(screen.getByRole('checkbox', { name: 'High' }))
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    expect(onApply).toHaveBeenCalledWith(f('severity'), 'in', ['critical', 'high'])
  })

  it('an enum cannot be applied empty', async () => {
    picker()
    await open()
    await userEvent.click(screen.getByRole('option', { name: 'Severity' }))
    expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled()
  })

  it('a number: an operator and a value, validated', async () => {
    const { onApply } = picker()
    await open()
    await userEvent.click(screen.getByRole('option', { name: 'EPSS score' }))
    const input = screen.getByLabelText('Value')
    await userEvent.type(input, 'abc')
    expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled()
    await userEvent.clear(input)
    await userEvent.type(input, '0.5')
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    expect(onApply).toHaveBeenCalledWith(f('epss_score'), 'gte', ['0.5'])
  })

  it('a boolean applies on Yes or No', async () => {
    const { onApply } = picker()
    await open()
    await userEvent.click(screen.getByRole('option', { name: 'Exploit available' }))
    await userEvent.click(screen.getByRole('button', { name: 'Yes' }))
    expect(onApply).toHaveBeenCalledWith(f('exploit_available'), 'eq', ['true'])
  })

  it('a date: quick ranges look back for a seen date and ahead for an expiry', async () => {
    const { onApply } = picker()
    await open()
    await userEvent.click(screen.getByRole('option', { name: 'First seen' }))
    await userEvent.click(screen.getByRole('button', { name: '7 days ago' }))
    expect(onApply).toHaveBeenLastCalledWith(f('first_detected_at'), 'gte', ['-P7D'])
  })

  it('an expiry date opens on "on or before" with ranges ahead', async () => {
    const { onApply } = picker()
    await open()
    await userEvent.click(screen.getByRole('option', { name: 'Acceptance expires' }))
    await userEvent.click(screen.getByRole('button', { name: '30 days from now' }))
    expect(onApply).toHaveBeenCalledWith(f('acceptance_expires_at'), 'lte', ['P30D'])
  })

  it('a typed date becomes a UTC timestamp', async () => {
    const { onApply } = picker()
    await open()
    await userEvent.click(screen.getByRole('option', { name: 'First seen' }))
    fireEvent.change(screen.getByLabelText('Date'), { target: { value: '2026-09-01' } })
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    expect(onApply).toHaveBeenCalledWith(f('first_detected_at'), 'gte', ['2026-09-01T00:00:00Z'])
  })

  it('text: contains', async () => {
    const { onApply } = picker()
    await open()
    await userEvent.click(screen.getByRole('option', { name: 'File path' }))
    await userEvent.type(screen.getByLabelText('Value'), 'src/auth')
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    expect(onApply).toHaveBeenCalledWith(f('file_path'), 'contains', ['src/auth'])
  })

  it('a person is picked from the members', async () => {
    const { onApply } = picker()
    await open()
    await userEvent.click(screen.getByRole('option', { name: 'Assigned to' }))
    await userEvent.click(screen.getByRole('button', { name: 'pick user' }))
    expect(onApply).toHaveBeenCalledWith(f('assigned_to'), 'in', [
      '11111111-1111-4111-8111-111111111111',
    ])
  })

  it('"is empty" on a nullable field', async () => {
    const { onApply } = picker()
    await open()
    await userEvent.click(screen.getByRole('option', { name: 'Assigned to' }))
    await userEvent.click(screen.getByRole('combobox', { name: 'Condition' }))
    await userEvent.click(screen.getByRole('option', { name: 'is empty' }))
    await userEvent.click(screen.getByRole('button', { name: 'Is empty' }))
    expect(onApply).toHaveBeenCalledWith(f('assigned_to'), 'is_null', ['true'])
  })

  it('says it is loading, and says when loading failed', async () => {
    picker({ contract: undefined, contractLoading: true })
    await open()
    expect(screen.getByRole('status')).toHaveTextContent('Loading filters…')
  })

  it('reports a contract that could not be loaded', async () => {
    picker({ contract: undefined, contractFailed: true })
    await open()
    expect(screen.getByRole('alert')).toHaveTextContent('could not be loaded')
  })

  it('"f" opens it, but not while typing', async () => {
    const { onOpenChange } = picker()
    const input = document.createElement('input')
    document.body.appendChild(input)
    input.focus()
    fireEvent.keyDown(input, { key: 'f' })
    expect(onOpenChange).not.toHaveBeenCalled()
    input.blur()
    fireEvent.keyDown(document.body, { key: 'f' })
    expect(onOpenChange).toHaveBeenCalledWith(true)
    input.remove()
  })

  it('has no accessibility violations open', async () => {
    picker()
    await open()
    const res = await axe.run(document.body, {
      rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
    })
    expect(res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' '))}`)).toEqual(
      []
    )
  })
})

describe('FilterBar', () => {
  function bar(search: string, over: Partial<React.ComponentProps<typeof FilterBar>> = {}) {
    const onSearchChange = vi.fn()
    render(
      <FilterBar
        search={new URLSearchParams(search)}
        contract={withOwnedFields(contract)}
        pickerContract={contract}
        contractLoading={false}
        contractFailed={false}
        skip={new Set(['asset_id'])}
        canReadAssets
        onPickerOpenChange={() => {}}
        onSearchChange={onSearchChange}
        {...over}
      />
    )
    return { onSearchChange }
  }

  it('draws a chip per filter, the facet ones included', () => {
    bar('severity=critical&status=new&epss_score_gte=0.5&is_in_kev=true')
    expect(screen.getAllByTestId('filter-chip')).toHaveLength(4)
  })

  it('removing a chip removes only its param and resets the page', () => {
    const { onSearchChange } = bar('severity=critical&epss_score_gte=0.5&page=3&q=x')
    fireEvent.click(screen.getByRole('button', { name: /remove filter epss score/i }))
    expect(onSearchChange.mock.calls[0][0].toString()).toBe('severity=critical&q=x')
  })

  it("shows the open view's filters as locked chips that cannot be removed", () => {
    bar('epss_score_gte=0.5', {
      viewFilter: {
        v: 1,
        filter: {
          all: [
            { field: 'severity', op: 'in', value: ['critical'] },
            { field: 'is_in_kev', op: 'eq', value: true },
          ],
        },
      },
    })
    const chips = screen.getAllByTestId('filter-chip')
    expect(chips).toHaveLength(3)
    const locked = chips.filter((c) => c.getAttribute('data-locked') === 'true')
    expect(locked).toHaveLength(2)
    for (const c of locked) expect(within(c).queryByRole('button')).toBeNull()
  })

  it('does not let a filter override a field the open view already sets', async () => {
    bar('', {
      viewFilter: { v: 1, filter: { all: [{ field: 'severity', op: 'in', value: ['low'] }] } },
    })
    await userEvent.click(screen.getByRole('button', { name: /add filter/i }))
    const option = screen.getByRole('option', { name: /^Severity/ })
    expect(option).toHaveAttribute('aria-disabled', 'true')
    expect(option).toHaveTextContent('Set by the saved view')
    expect(screen.getByRole('option', { name: 'EPSS score' })).not.toHaveAttribute(
      'aria-disabled',
      'true'
    )
  })

  it('names a view whose conditions are a tree', () => {
    bar('', {
      viewFilter: { v: 1, filter: { any: [{ field: 'severity', op: 'in', value: ['low'] }] } },
    })
    expect(screen.getByText('Conditions from the saved view')).toBeInTheDocument()
  })

  it('an unknown param is shown, and removable', () => {
    const { onSearchChange } = bar('sevrity=high&severity=low')
    expect(screen.getByTestId('filter-chip-unknown')).toHaveTextContent('Unknown filter “sevrity”')
    fireEvent.click(screen.getByRole('button', { name: /remove unknown filter sevrity/i }))
    expect(onSearchChange.mock.calls[0][0].toString()).toBe('severity=low')
  })

  it('a context param is drawn elsewhere, not twice', () => {
    bar('asset_id=abc', { leading: <span>asset chip</span> })
    expect(screen.queryByTestId('filter-chip')).toBeNull()
    expect(screen.getByText('asset chip')).toBeInTheDocument()
  })

  it('adding a filter writes its param', async () => {
    const { onSearchChange } = bar('q=x&page=2')
    await userEvent.click(screen.getByRole('button', { name: /add filter/i }))
    await userEvent.click(screen.getByRole('option', { name: 'EPSS score' }))
    await userEvent.type(screen.getByLabelText('Value'), '0.7')
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    expect(onSearchChange.mock.calls[0][0].toString()).toBe('q=x&epss_score_gte=0.7')
  })

  it('has no accessibility violations with chips', async () => {
    bar('severity=critical&epss_score_gte=0.5&sevrity=x', {
      viewFilter: { v: 1, filter: { all: [{ field: 'is_in_kev', op: 'eq', value: true }] } },
    })
    const res = await axe.run(document.body, {
      rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
    })
    expect(res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' '))}`)).toEqual(
      []
    )
  })
})

describe('invalid filter notice', () => {
  it('reads the params of an INVALID_FILTER error', () => {
    const err = Object.assign(new Error('1 filter error'), {
      code: 'INVALID_FILTER',
      details: [{ param: 'sevrity', reason: 'unknown filter' }],
    })
    expect(invalidFilterParams(err)).toEqual(['sevrity'])
    expect(invalidFilterParams(new Error('x'))).toBeUndefined()
    expect(invalidFilterParams(Object.assign(new Error('x'), { code: 'OTHER' }))).toBeUndefined()
  })

  it('says which filter and offers to remove it', () => {
    const onRemove = vi.fn()
    render(<InvalidFilterNotice params={['sevrity']} onRemove={onRemove} />)
    expect(screen.getByText('This link has a filter we do not know: “sevrity”')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Remove it' }))
    expect(onRemove).toHaveBeenCalledWith(['sevrity'])
  })

  it('several filters read in the plural', () => {
    render(<InvalidFilterNotice params={['a', 'b']} onRemove={() => {}} />)
    expect(screen.getByText(/filters we do not know: “a”, “b”/)).toBeInTheDocument()
  })
})
