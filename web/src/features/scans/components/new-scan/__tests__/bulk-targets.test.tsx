import { useState } from 'react'
import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { ApiScopeCheckResult } from '@/features/scope'
import { BulkTargetsPanel } from '../bulk-targets-panel'
import { TargetList } from '../target-list'
import { PasteSource } from '../../target-picker/paste-source'
import { parsePastedTargets, replaceEntryInLines } from '../../../lib/target-format'
import { InvalidTargetsNote } from '../invalid-targets-note'

function PasteHarness({ initial = [] as string[] }) {
  const [lines, setLines] = useState<string[]>(initial)
  return (
    <>
      <PasteSource value={lines} onChange={setLines} />
      <output data-testid="lines">{lines.join('|')}</output>
    </>
  )
}

describe('PasteSource', () => {
  it('counts each kind, folds repeats and lists what will not be added with the reason', () => {
    render(
      <PasteHarness
        initial={[
          'a.example.com, b.example.com',
          'A.example.com.',
          '203.0.113.0/24',
          '[2001:db8::1]:443',
          'bücher.de',
          '10.0.0.0/8',
          'git@code.example.com:t/app.git',
        ]}
      />
    )
    const counts = screen.getByTestId('paste-counts')
    expect(counts).toHaveTextContent('5 targets')
    expect(counts).toHaveTextContent('3 Domain')
    expect(counts).toHaveTextContent('1 CIDR')
    expect(counts).toHaveTextContent('1 Host:port')
    expect(counts).toHaveTextContent(/1 repeated/i)
    expect(screen.getByText('2 entries will not be added')).toBeInTheDocument()
    const list = screen.getByTestId('paste-invalid-list')
    expect(within(list).getByText('10.0.0.0/8')).toBeInTheDocument()
    expect(
      within(list).getByText(
        /has 16,777,216 addresses; the most one target can hold is 65,536 \(\/16\)/
      )
    ).toBeInTheDocument()
    expect(
      within(list).getByText(/repositories are scanned from repository assets/)
    ).toBeInTheDocument()
  })

  it('removes all entries that will not be added in one go', async () => {
    const user = userEvent.setup()
    render(<PasteHarness initial={['a.example.com', 'b@d', '10.0.0.0/8']} />)
    await user.click(screen.getByRole('button', { name: 'Remove all' }))
    expect(screen.getByTestId('lines')).toHaveTextContent(/^a\.example\.com$/)
  })

  it('fixes one entry in place', async () => {
    const user = userEvent.setup()
    render(<PasteHarness initial={['a.example.com, 10.0.0.0/8']} />)
    await user.click(screen.getByRole('button', { name: 'Edit 10.0.0.0/8' }))
    const field = screen.getByRole('textbox', { name: 'Edit 10.0.0.0/8' })
    await user.clear(field)
    await user.type(field, '10.0.0.0/16{Enter}')
    expect(screen.getByTestId('lines')).toHaveTextContent('a.example.com, 10.0.0.0/16')
  })

  it('reads an uploaded CSV in the browser, keeping the target column', async () => {
    render(<PasteHarness />)
    const file = new File(['host,owner\na.example.com,web\nb.example.com,ops\n'], 'hosts.csv', {
      type: 'text/csv',
    })
    fireEvent.change(screen.getByTestId('target-file-input'), { target: { files: [file] } })
    await vi.waitFor(() =>
      expect(screen.getByTestId('lines')).toHaveTextContent('a.example.com|b.example.com')
    )
    expect(screen.getByText(/2 entries read from hosts.csv/)).toBeInTheDocument()
  })

  it('refuses a file that is not .txt or .csv, or is larger than 1 MB', async () => {
    render(<PasteHarness />)
    const input = screen.getByTestId('target-file-input')
    fireEvent.change(input, { target: { files: [new File(['x'], 'list.xlsx')] } })
    expect(await screen.findByRole('alert')).toHaveTextContent('Only .txt and .csv')
    const big = new File(['a'.repeat(1024 * 1024 + 1)], 'big.txt', { type: 'text/plain' })
    fireEvent.change(input, { target: { files: [big] } })
    expect(await screen.findByRole('alert')).toHaveTextContent('big.txt is larger than 1 MB')
    expect(screen.getByTestId('lines')).toHaveTextContent(/^$/)
  })
})

describe('BulkTargetsPanel', () => {
  it('adds only new targets, saying how many are already in the scan', async () => {
    const user = userEvent.setup()
    const onAdd = vi.fn()
    render(
      <BulkTargetsPanel
        id="bulk"
        present={['a.example.com']}
        capacity={1000}
        onAdd={onAdd}
        onCancel={vi.fn()}
      />
    )
    const box = screen.getByRole('textbox')
    await user.click(box)
    await user.paste('a.example.com\nb.example.com\nc.example.com')
    expect(screen.getByText(/1 target is already in the scan/)).toBeInTheDocument()
    await user.click(screen.getByTestId('bulk-add'))
    expect(onAdd).toHaveBeenCalledWith(['b.example.com', 'c.example.com'])
  })

  it('stops a list over the scan limit with the reason', async () => {
    const user = userEvent.setup()
    render(
      <BulkTargetsPanel id="bulk" present={[]} capacity={2} onAdd={vi.fn()} onCancel={vi.fn()} />
    )
    await user.click(screen.getByRole('textbox'))
    await user.paste('a.example.com b.example.com c.example.com')
    expect(screen.getByTestId('bulk-add')).toBeDisabled()
    expect(screen.getByRole('alert')).toHaveTextContent('room for 2 more')
  })
})

describe('TargetList', () => {
  const entries = parsePastedTargets([
    'app.example.com',
    'shop.other.org',
    'new.example.com',
    '10.0.0.0/8',
  ])
  const list = [...entries.invalid, ...entries.lines.filter((l) => l.kind !== 'invalid')]
  const results: Record<string, ApiScopeCheckResult> = {
    'app.example.com': {
      target: 'app.example.com',
      allowed: true,
      via: { kind: 'rule', pattern: '*.example.com' },
    } as ApiScopeCheckResult,
    'shop.other.org': {
      target: 'shop.other.org',
      allowed: false,
      code: 'not_in_scope',
    } as ApiScopeCheckResult,
  }
  const resultFor = (x: string) => results[x]

  it('shows each target with its kind and the scope answer, with the reason', () => {
    render(
      <TargetList
        entries={list}
        resultFor={resultFor}
        checking
        onRemove={vi.fn()}
        onReplace={vi.fn()}
      />
    )
    const rows = screen.getByTestId('target-list-rows')
    const row = (name: string) =>
      within(rows).getByText(name).closest('[data-state]') as HTMLElement
    expect(row('app.example.com')).toHaveAttribute('data-state', 'allowed')
    expect(row('app.example.com')).toHaveTextContent('In scope, by *.example.com')
    expect(row('shop.other.org')).toHaveAttribute('data-state', 'refused')
    expect(row('new.example.com')).toHaveTextContent('Checking scope')
    expect(row('10.0.0.0/8')).toHaveAttribute('data-state', 'invalid')
  })

  it('says "not checked" when the caller cannot run the check', () => {
    render(
      <TargetList entries={list} checkAvailable={false} onRemove={vi.fn()} onReplace={vi.fn()} />
    )
    expect(screen.getAllByText(/Scope not checked/).length).toBe(3)
  })

  it('filters to what needs attention and searches', async () => {
    const user = userEvent.setup()
    render(
      <TargetList entries={list} resultFor={resultFor} onRemove={vi.fn()} onReplace={vi.fn()} />
    )
    await user.click(screen.getByTestId('target-list-attention'))
    const rows = screen.getByTestId('target-list-rows')
    expect(within(rows).queryByText('app.example.com')).not.toBeInTheDocument()
    expect(within(rows).getByText('shop.other.org')).toBeInTheDocument()
    expect(within(rows).getByText('10.0.0.0/8')).toBeInTheDocument()
    await user.type(screen.getByRole('searchbox', { name: 'Search targets' }), 'shop')
    expect(within(rows).queryByText('10.0.0.0/8')).not.toBeInTheDocument()
  })

  it('removes a target and edits an invalid one', async () => {
    const user = userEvent.setup()
    const onRemove = vi.fn()
    const onReplace = vi.fn()
    render(
      <TargetList entries={list} resultFor={resultFor} onRemove={onRemove} onReplace={onReplace} />
    )
    await user.click(screen.getByRole('button', { name: 'Remove shop.other.org' }))
    expect(onRemove).toHaveBeenCalledWith(expect.objectContaining({ value: 'shop.other.org' }))
    await user.click(screen.getByRole('button', { name: 'Edit 10.0.0.0/8' }))
    const field = screen.getByRole('textbox', { name: 'Edit 10.0.0.0/8' })
    await user.clear(field)
    await user.type(field, '10.0.0.0/16{Enter}')
    expect(onReplace).toHaveBeenCalledWith(
      expect.objectContaining({ input: '10.0.0.0/8' }),
      '10.0.0.0/16'
    )
  })

  it('keeps only the visible rows of a long list in the page', () => {
    const many = parsePastedTargets(Array.from({ length: 1000 }, (_, i) => `h${i}.example.com`))
    render(<TargetList entries={many.lines} onRemove={vi.fn()} onReplace={vi.fn()} />)
    const rows = screen.getByTestId('target-list-rows')
    const items = within(rows).getAllByRole('listitem')
    expect(items.length).toBeLessThan(40)
    expect(items[0]).toHaveAttribute('aria-setsize', '1000')
  })
})

describe('a range wider than one target', () => {
  function StepHarness({ initial }: { initial: string[] }) {
    const [lines, setLines] = useState<string[]>(initial)
    const pasted = parsePastedTargets(lines)
    return (
      <>
        <InvalidTargetsNote
          entries={pasted.invalid}
          onSplit={(entry, pieces) =>
            setLines(replaceEntryInLines(lines, entry.input, pieces.join(', ')))
          }
        />
        <output data-testid="lines">{lines.join('|')}</output>
      </>
    )
  }

  it('says why inline and splits it into /16 ranges in one click', async () => {
    render(<StepHarness initial={['10.0.0.0/14']} />)
    const note = screen.getByTestId('invalid-targets')
    expect(note).toHaveTextContent(
      '10.0.0.0/14 has 262,144 addresses; the most one target can hold is 65,536 (/16)'
    )
    expect(note).not.toHaveTextContent('under Paste')
    await userEvent.click(screen.getByRole('button', { name: 'Split into 4 /16 ranges' }))
    expect(screen.getByTestId('lines')).toHaveTextContent(
      '10.0.0.0/16, 10.1.0.0/16, 10.2.0.0/16, 10.3.0.0/16'
    )
    expect(screen.queryByTestId('invalid-targets')).toBeNull()
  })

  it('offers 256 /16 ranges for a /8, and no split for a /7', () => {
    render(<StepHarness initial={['10.0.0.0/8', '10.0.0.0/7']} />)
    expect(screen.getByRole('button', { name: 'Split into 256 /16 ranges' })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /^Split into/ })).toHaveLength(1)
  })

  it('names three entries and counts the rest', () => {
    render(<StepHarness initial={['a@b', 'c@d', 'e@f', 'g@h', 'i@j']} />)
    expect(screen.getByTestId('invalid-targets')).toHaveTextContent(
      '2 more typed lines are not targets.'
    )
  })

  it('splits from the paste list too', async () => {
    render(<PasteHarness initial={['10.0.0.0/15']} />)
    await userEvent.click(screen.getByRole('button', { name: 'Split into 2 /16 ranges' }))
    expect(screen.getByTestId('lines')).toHaveTextContent('10.0.0.0/16, 10.1.0.0/16')
  })
})
