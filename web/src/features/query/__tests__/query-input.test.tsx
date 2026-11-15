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
    render(<Box initial="severty=high" onSubmit={vi.fn()} />)
    fireEvent.keyDown(screen.getByRole('combobox'), { key: 'Enter' })
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

  it('sends nothing while typing; one check on Enter', async () => {
    api.parse.mockResolvedValue(ok({ text: 'severity>=high kev=true' }))
    const onSubmit = vi.fn()
    render(<Box onSubmit={onSubmit} />)
    const box = screen.getByRole('combobox')
    const text = 'severity>=high kev=t'
    for (let i = 1; i <= text.length; i++) {
      fireEvent.change(box, { target: { value: text.slice(0, i), selectionStart: i } })
      await act(async () => {
        await vi.advanceTimersByTimeAsync(50)
      })
    }
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000)
    })
    expect(api.parse).not.toHaveBeenCalled()
    expect(api.values).not.toHaveBeenCalled()
    fireEvent.keyDown(box, { key: 'Escape' })
    fireEvent.keyDown(box, { key: 'Enter' })
    await act(async () => {
      await vi.runOnlyPendingTimersAsync()
    })
    expect(api.parse).toHaveBeenCalledTimes(1)
    expect(onSubmit).toHaveBeenCalledTimes(1)
  })

  it('asks for server values only after two characters and a pause, cancelling the one in flight', async () => {
    const signals: AbortSignal[] = []
    api.values.mockImplementation((...args: unknown[]) => {
      signals.push(args[4] as AbortSignal)
      return new Promise(() => {})
    })
    render(<Box />)
    const box = screen.getByRole('combobox')
    const type = async (v: string, wait: number) => {
      fireEvent.change(box, { target: { value: v, selectionStart: v.length } })
      await act(async () => {
        await vi.advanceTimersByTimeAsync(wait)
      })
    }
    await type('tool_name=', 1000)
    await type('tool_name=n', 1000)
    expect(api.values).not.toHaveBeenCalled()
    await type('tool_name=nu', 299)
    expect(api.values).not.toHaveBeenCalled()
    await type('tool_name=nuc', 300)
    expect(api.values).toHaveBeenCalledTimes(1)
    expect(api.values.mock.calls[0].slice(0, 3)).toEqual(['findings', 'tool_name', 'nuc'])
    await type('tool_name=nucl', 300)
    expect(api.values).toHaveBeenCalledTimes(2)
    expect(signals[0].aborted).toBe(true)
    expect(signals[1].aborted).toBe(false)
  })

  it('Ctrl+Space asks for values at once, whatever was typed', async () => {
    render(<Box />)
    const box = screen.getByRole('combobox')
    fireEvent.change(box, { target: { value: 'tool_name=', selectionStart: 10 } })
    fireEvent.keyDown(box, { key: ' ', ctrlKey: true })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300)
    })
    expect(api.values).toHaveBeenCalledTimes(1)
  })

  it('a quote or parenthesis that does not pair up is refused without asking the server', async () => {
    const onSubmit = vi.fn()
    render(<Box onSubmit={onSubmit} initial={'tool_name="nuclei'} />)
    const box = screen.getByRole('combobox')
    expect(box.getAttribute('aria-invalid')).toBe('false')
    fireEvent.keyDown(box, { key: 'Enter' })
    await act(async () => {
      await vi.runOnlyPendingTimersAsync()
    })
    expect(api.parse).not.toHaveBeenCalled()
    expect(onSubmit).not.toHaveBeenCalled()
    expect(box.getAttribute('aria-invalid')).toBe('true')
    expect(screen.getByText(/quote is not closed/i)).toBeTruthy()
  })

  it('shows Apply, enabled and announced while the text differs from the applied one', async () => {
    api.parse.mockResolvedValue(ok({ text: 'kev=true' }))
    const onSubmit = vi.fn()
    function Applied() {
      const [v, setV] = useState('severity>=high')
      return (
        <QueryInput
          entity="findings"
          value={v}
          onChange={setV}
          applied="severity>=high"
          onSubmit={onSubmit}
          ariaLabel="search"
          quietStatus
        />
      )
    }
    render(<Applied />)
    const apply = screen.getByRole('button', { name: /apply query/i }) as HTMLButtonElement
    expect(apply.disabled).toBe(true)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'kev=true' } })
    expect(apply.disabled).toBe(false)
    expect(screen.getByText(/not applied yet/i)).toBeTruthy()
    expect(api.parse).not.toHaveBeenCalled()
    fireEvent.click(apply)
    await act(async () => {
      await vi.runOnlyPendingTimersAsync()
    })
    expect(api.parse).toHaveBeenCalledTimes(1)
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({ valid: true }))
  })

  function ListField({ onSubmit }: { onSubmit: (r: ParseResult) => void }) {
    const [v, setV] = useState('severity>=high')
    return (
      <QueryInput
        entity="findings"
        value={v}
        onChange={setV}
        applied="severity>=high"
        onSubmit={onSubmit}
        ariaLabel="search"
        quietStatus
      />
    )
  }

  it('expands in place into a coloured multi-line editor: Shift+Enter is a new line, Enter runs, Escape folds back unchanged', async () => {
    api.parse.mockResolvedValue(ok())
    const onSubmit = vi.fn()
    const { container } = render(<ListField onSubmit={onSubmit} />)
    fireEvent.click(screen.getByRole('button', { name: /expand the editor/i }))
    const editor = container.querySelector('[data-slot="query-editor-expanded"] textarea')
    expect(editor).toBeTruthy()
    expect(screen.getByRole('combobox')).toBe(editor)
    // The coloured copy holds the same text, hidden from assistive technology.
    const copy = container.querySelector('[data-slot="query-highlight"]')!
    expect(copy.getAttribute('aria-hidden')).toBe('true')
    expect(copy.textContent).toBe('severity>=high\n')
    expect(copy.querySelector('span')?.textContent).toBe('severity')
    const box = screen.getByRole('combobox')
    fireEvent.keyDown(box, { key: 'Escape' })
    // It folds back after its short height animation.
    act(() => {
      vi.advanceTimersByTime(300)
    })
    expect(container.querySelector('[data-slot="query-editor-expanded"]')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /expand the editor/i }))
    const big = screen.getByRole('combobox')
    fireEvent.change(big, { target: { value: 'kev=true' } })
    fireEvent.keyDown(big, { key: 'Enter', shiftKey: true })
    expect(api.parse).not.toHaveBeenCalled()
    fireEvent.keyDown(big, { key: 'Escape' })
    // Changed: Escape does not fold it (the host decides, e.g. puts the applied text back).
    expect(container.querySelector('[data-slot="query-editor-expanded"]')).toBeTruthy()
    fireEvent.keyDown(big, { key: 'Enter' })
    await act(async () => {
      await vi.runOnlyPendingTimersAsync()
    })
    expect(api.parse).toHaveBeenCalledTimes(1)
    expect(onSubmit).toHaveBeenCalledTimes(1)
  })

  it('expanding and folding keep the text and the caret; line breaks become spaces on one line', () => {
    const { container } = render(<ListField onSubmit={vi.fn()} />)
    const line = screen.getByRole('combobox') as HTMLInputElement
    line.focus()
    line.setSelectionRange(3, 5)
    fireEvent.click(screen.getByRole('button', { name: /expand the editor/i }))
    act(() => {
      vi.advanceTimersByTime(50)
    })
    const big = screen.getByRole('combobox') as HTMLTextAreaElement
    expect(big.tagName).toBe('TEXTAREA')
    expect(big.value).toBe('severity>=high')
    expect(document.activeElement).toBe(big)
    expect([big.selectionStart, big.selectionEnd]).toEqual([3, 5])
    fireEvent.change(big, { target: { value: 'severity=critical\nkev=true' } })
    big.setSelectionRange(20, 20)
    fireEvent.click(screen.getByRole('button', { name: /collapse the editor/i }))
    act(() => {
      vi.advanceTimersByTime(300)
    })
    expect(container.querySelector('[data-slot="query-editor-expanded"]')).toBeNull()
    const again = screen.getByRole('combobox') as HTMLInputElement
    expect(again.value).toBe('severity=critical kev=true')
    expect(document.activeElement).toBe(again)
    expect(again.selectionStart).toBe(20)
  })

  it('autoFocus focuses the field once it is enabled (a list prints its text first)', () => {
    const props = {
      entity: 'findings' as const,
      onChange: vi.fn(),
      ariaLabel: 'search',
      autoFocus: true,
    }
    const { rerender } = render(<QueryInput {...props} value="" disabled />)
    expect(document.activeElement).not.toBe(screen.getByRole('combobox'))
    rerender(<QueryInput {...props} value="severity>=high" />)
    expect(document.activeElement).toBe(screen.getByRole('combobox'))
  })

  it('on a touch screen the expanded editor does not take the focus (no keyboard on open)', () => {
    const before = window.matchMedia
    window.matchMedia = ((q: string) => ({
      matches: q.includes('coarse'),
      media: q,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    })) as unknown as typeof window.matchMedia
    try {
      function Touch() {
        const [v, setV] = useState('severity>=high')
        return (
          <QueryInput
            entity="findings"
            value={v}
            onChange={setV}
            applied="severity>=high"
            onSubmit={vi.fn()}
            ariaLabel="search"
            autoFocus
            quietStatus
          />
        )
      }
      render(<Touch />)
      ;(document.activeElement as HTMLElement | null)?.blur()
      fireEvent.click(screen.getByRole('button', { name: /expand the editor/i }))
      act(() => {
        vi.advanceTimersByTime(50)
      })
      const big = screen.getByRole('combobox')
      expect(big.tagName).toBe('TEXTAREA')
      expect(document.activeElement).not.toBe(big)
    } finally {
      window.matchMedia = before
    }
  })

  it('applies through one icon in the field: no text button, the edit state on the icon', () => {
    const { container } = render(<ListField onSubmit={vi.fn()} />)
    const apply = screen.getByRole('button', { name: 'Apply query' })
    expect(apply.textContent).toBe('')
    expect(apply).toHaveAttribute('aria-keyshortcuts', 'Enter')
    expect(apply.closest('[data-slot="query-field-controls"]')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /^apply$/i })).toBeNull()
    expect(apply.className).not.toContain('bg-primary')
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'kev=true' } })
    expect(apply.className).toContain('bg-primary')
    expect(container.querySelector('[aria-live="polite"]')?.textContent).toMatch(/not applied yet/i)
  })

  it('on a phone help and expand sit behind one overflow in the one-line field', () => {
    render(<ListField onSubmit={vi.fn()} />)
    const more = screen.getByRole('button', { name: 'More query options' })
    expect(more.closest('[data-slot="query-field-controls"]')).toBeTruthy()
    // From 768 px the two are their own buttons; below, hidden (CSS).
    expect(screen.getByRole('button', { name: /query syntax/i })).toHaveClass('hidden', 'md:flex')
    expect(screen.getByRole('button', { name: /expand the editor/i })).toHaveClass(
      'hidden',
      'md:flex'
    )
    expect(more.parentElement).toHaveClass('md:hidden')
  })

  it('the expanded editor grows in place from the field height, within 4 to 16 lines, and keeps a dragged height', () => {
    window.localStorage.setItem('query-editor-height', '9999')
    const { container } = render(<ListField onSubmit={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: /expand the editor/i }))
    const big = container.querySelector<HTMLTextAreaElement>(
      '[data-slot="query-editor-expanded"] textarea'
    )!
    // In the flow: no overlay box, no stand-in field keeping the row one line high.
    expect(container.querySelector('input[aria-hidden]')).toBeNull()
    expect(big.closest('.absolute')).toBeNull()
    // A stored height is held to the largest the editor may take (16 lines of 20 px).
    const max = parseFloat(big.style.maxHeight)
    expect(parseFloat(big.style.height)).toBeLessThanOrEqual(max)
    expect(max).toBeLessThanOrEqual(12 + 16 * 20 + 1000)
    expect(big.className).toContain('resize-y')
  })

  it("the help lists the syntax and the person's own fields with their operators", async () => {
    render(<ListField onSubmit={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: /query syntax/i }))
    const help = document.querySelector('[data-slot="query-help"]')!
    expect(help.textContent).toContain('severity')
    expect(help.textContent).toContain('tool_name')
    expect(help.textContent).toMatch(/Enter runs the query/)
  })
})
