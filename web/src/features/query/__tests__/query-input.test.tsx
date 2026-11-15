import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { QueryInput } from '../components/query-input'
import type { ParseResult } from '../api/query-api'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

const api = vi.hoisted(() => ({ parse: vi.fn(), values: vi.fn() }))
vi.mock('../api/query-api', () => ({
  queryApi: api,
  useQuerySchema: () => ({
    data: {
      fields: [
        {
          path: 'severity',
          type: 'enum',
          operators: ['=', 'in'],
          enum: ['critical', 'high', 'medium', 'low', 'info'],
        },
        { path: 'tool_name', type: 'string', operators: ['=', 'in'] },
      ],
    },
  }),
}))

function ok(over: Partial<ParseResult> = {}): ParseResult {
  return {
    entity: 'findings',
    valid: true,
    form: 'short',
    text: 'severity>=high',
    query: 'findings where severity in (critical, high)',
    chips: [],
    advanced: false,
    problems: [],
    ...over,
  }
}

function Box(props: { onSubmit?: (r: ParseResult) => void; initial?: string }) {
  const [v, setV] = useState(props.initial ?? '')
  return (
    <QueryInput
      entity="findings"
      value={v}
      onChange={setV}
      onSubmit={props.onSubmit}
      ariaLabel="search"
    />
  )
}

describe('QueryInput', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    api.parse.mockReset()
    api.values.mockReset()
    api.parse.mockReturnValue(new Promise(() => {}))
    api.values.mockReturnValue(new Promise(() => {}))
    window.localStorage.clear()
  })

  it('suggests fields, then values, and accepts with Tab', async () => {
    render(<Box />)
    const box = screen.getByRole('combobox')
    fireEvent.change(box, { target: { value: 'sev', selectionStart: 3 } })
    expect(screen.getByRole('option', { name: /severity/ })).toBeTruthy()
    fireEvent.keyDown(box, { key: 'Tab' })
    await act(async () => {
      await vi.runOnlyPendingTimersAsync()
    })
    expect((box as HTMLInputElement).value).toBe('severity')
  })

  it("shows the first problem in the person's language with its fix, never the server text alone", async () => {
    api.parse.mockResolvedValue(
      ok({
        valid: false,
        problems: [
          {
            code: 'unknown_field',
            message: 'unknown field "severty" on findings',
            start: 0,
            end: 7,
            line: 1,
            column: 1,
            suggestions: ['severity'],
          },
        ],
      })
    )
    render(<Box initial="severty=high" />)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300)
    })
    const fix = screen.getByRole('button', { name: 'severity' })
    fireEvent.click(fix)
    await act(async () => {
      await vi.runOnlyPendingTimersAsync()
    })
    expect((screen.getByRole('combobox') as HTMLInputElement).value).toBe('severity=high')
    expect(screen.queryByText(/on findings/)).toBeNull()
  })

  it('submits a valid filter on Enter and remembers it', async () => {
    api.parse.mockResolvedValue(ok())
    const onSubmit = vi.fn()
    render(<Box onSubmit={onSubmit} initial="severity>=high" />)
    fireEvent.keyDown(screen.getByRole('combobox'), { key: 'Enter' })
    await act(async () => {
      await vi.runOnlyPendingTimersAsync()
    })
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({ valid: true }))
    expect(window.localStorage.getItem('recent-queries:findings')).toContain('severity>=high')
  })

  it('draws the suggestions as a floating list in a portal, sized by the room and the field', () => {
    const { container } = render(<Box />)
    const box = screen.getByRole('combobox')
    expect(box.getAttribute('aria-controls')).toBeNull()
    fireEvent.change(box, { target: { value: 'sev', selectionStart: 3 } })
    const list = screen.getByRole('listbox')
    // Outside the field's own tree: no scroll container around the field
    // (a dialog body) can clip it.
    expect(container.contains(list)).toBe(false)
    expect(document.body.contains(list)).toBe(true)
    expect(box.getAttribute('aria-controls')).toBe(list.id)
    expect(box.getAttribute('aria-activedescendant')).toBe(`${list.id}-0`)
    expect(list.className).toContain('--radix-popover-content-available-height')
    expect(list.className).toContain('--radix-popover-trigger-width')
    expect(list.className).toContain('overflow-y-auto')
    // It never takes focus: the caret stays in the field.
    expect(document.activeElement).not.toBe(list)
  })

  it('Escape closes the suggestions first and keeps the dialog open', async () => {
    const onOpenChange = vi.fn()
    function InDialog() {
      const [v, setV] = useState('')
      return (
        <Dialog open onOpenChange={onOpenChange}>
          <DialogContent size="xl">
            <DialogHeader>
              <DialogTitle>title</DialogTitle>
              <DialogDescription>description</DialogDescription>
            </DialogHeader>
            <DialogBody>
              <QueryInput entity="findings" value={v} onChange={setV} multiline ariaLabel="q" />
            </DialogBody>
          </DialogContent>
        </Dialog>
      )
    }
    render(<InDialog />)
    const box = screen.getByRole('combobox')
    fireEvent.change(box, { target: { value: 'sev', selectionStart: 3 } })
    expect(screen.getByRole('listbox')).toBeTruthy()
    fireEvent.keyDown(box, { key: 'Escape' })
    expect(screen.queryByRole('listbox')).toBeNull()
    expect(onOpenChange).not.toHaveBeenCalled()
    fireEvent.keyDown(box, { key: 'Escape' })
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('drops a stale answer', async () => {
    let first!: (r: ParseResult) => void
    api.parse
      .mockImplementationOnce(() => new Promise<ParseResult>((r) => (first = r)))
      .mockResolvedValueOnce(ok({ text: 'kev=true' }))
    const onParsed = vi.fn()
    function Two() {
      const [v, setV] = useState('severity=x')
      return (
        <>
          <QueryInput
            entity="findings"
            value={v}
            onChange={setV}
            onParsed={onParsed}
            ariaLabel="search"
          />
          <button onClick={() => setV('kev=true')}>next</button>
        </>
      )
    }
    render(<Two />)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300)
    })
    fireEvent.click(screen.getByText('next'))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300)
    })
    await act(async () => {
      first(
        ok({
          valid: false,
          problems: [
            { code: 'unknown_value', message: '', start: 9, end: 10, line: 1, column: 10 },
          ],
        })
      )
    })
    expect(onParsed).toHaveBeenLastCalledWith(expect.objectContaining({ text: 'kev=true' }))
  })
})
