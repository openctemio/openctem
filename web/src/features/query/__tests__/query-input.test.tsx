import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { QueryInput } from '../components/query-input'
import type { ParseResult } from '../api/query-api'

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
