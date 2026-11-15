import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { ListSearch } from '@/features/shared/components/list-search'
import { joinFilterText, useListQueryMode } from '../components/query-mode'
import type { ParseRequest, ParseResult } from '../api/query-api'

const api = vi.hoisted(() => ({ parse: vi.fn(), values: vi.fn() }))
vi.mock('../api/query-api', () => ({
  queryApi: api,
  useQuerySchema: () => ({ data: { fields: [] } }),
}))

function result(over: Partial<ParseResult> = {}): ParseResult {
  return {
    entity: 'findings',
    valid: true,
    text: '',
    query: '',
    chips: [],
    advanced: false,
    problems: [],
    ...over,
  }
}

// Answers of POST /query/parse recorded from the server (findings entity).
const PRINTED = result({
  text: 'practice!=compliance severity=critical state=open',
  params: { practice_not: 'compliance', severity: 'critical', state: 'open' },
})
const KEV = result({ text: 'is_in_kev=true', params: { is_in_kev: 'true' } })
const REFUSED = result({
  valid: false,
  problems: [
    {
      code: 'unknown_value',
      message: 'must be one of: critical, high, medium, low, info, none',
      start: 10,
      end: 13,
      line: 1,
      column: 11,
    },
  ],
})

/** The server: params print as PRINTED; texts answer from a table. */
function serve(texts: Record<string, ParseResult>) {
  api.parse.mockImplementation((req: ParseRequest) =>
    Promise.resolve(req.params !== undefined ? PRINTED : (texts[req.text ?? ''] ?? REFUSED))
  )
}

function Harness({
  onApply,
  fq = null,
}: {
  onApply: (r: ParseResult) => void
  fq?: string | null
}) {
  const mode = useListQueryMode({
    entity: 'findings',
    fq,
    params: 'severity=critical&state=open&practice_not=compliance',
    onApply,
    testId: 'q-editor',
  })
  return (
    <ListSearch
      value=""
      onChange={() => undefined}
      placeholder="Search findings"
      query={mode.query}
    />
  )
}

async function settle() {
  // The editor loads on use (a lazy chunk).
  await act(async () => {
    await vi.dynamicImportSettled()
    await vi.advanceTimersByTimeAsync(400)
  })
}

const box = () => screen.getByRole('combobox') as HTMLInputElement
const basic = () => screen.getByRole('button', { name: 'Basic' })
const query = () => screen.getByRole('button', { name: 'Query' })

describe('the list search field Query mode', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    api.parse.mockReset()
    api.values.mockReset()
    api.values.mockReturnValue(new Promise(() => {}))
    window.localStorage.clear()
  })

  it('Basic to Query shows the filter printed by the server from the page params', async () => {
    serve({})
    render(<Harness onApply={vi.fn()} />)
    expect(basic()).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(query())
    await settle()
    expect(api.parse).toHaveBeenCalledWith({
      entity: 'findings',
      params: 'severity=critical&state=open&practice_not=compliance',
    })
    expect(box().value).toBe('practice!=compliance severity=critical state=open')
    expect(query()).toHaveAttribute('aria-pressed', 'true')
  })

  it('round trip: back to Basic without an edit applies nothing', async () => {
    serve({})
    const onApply = vi.fn()
    render(<Harness onApply={onApply} />)
    fireEvent.click(query())
    await settle()
    fireEvent.click(basic())
    await settle()
    expect(onApply).not.toHaveBeenCalled()
    expect(basic()).toHaveAttribute('aria-pressed', 'true')
    expect(screen.queryByRole('combobox')).toBeNull()
  })

  it('Enter applies a valid text and stays in Query mode', async () => {
    serve({ 'kev=true': KEV })
    const onApply = vi.fn()
    render(<Harness onApply={onApply} />)
    fireEvent.click(query())
    await settle()
    fireEvent.change(box(), { target: { value: 'kev=true' } })
    fireEvent.keyDown(box(), { key: 'Enter' })
    await settle()
    expect(onApply).toHaveBeenCalledWith(KEV)
    expect(query()).toHaveAttribute('aria-pressed', 'true')
  })

  it('Query to Basic applies an edit not applied yet, so the switch drops nothing', async () => {
    serve({ 'kev=true': KEV })
    const onApply = vi.fn()
    render(<Harness onApply={onApply} />)
    fireEvent.click(query())
    await settle()
    fireEvent.change(box(), { target: { value: 'kev=true' } })
    fireEvent.click(basic())
    await settle()
    expect(onApply).toHaveBeenCalledWith(KEV)
    expect(basic()).toHaveAttribute('aria-pressed', 'true')
  })

  it('a text the parser refuses is never applied: inline problem with its column, field on the error', async () => {
    serve({})
    const onApply = vi.fn()
    render(<Harness onApply={onApply} />)
    fireEvent.click(query())
    await settle()
    fireEvent.change(box(), { target: { value: 'severity= AND kev=true' } })
    fireEvent.keyDown(box(), { key: 'Enter' })
    await settle()
    expect(onApply).not.toHaveBeenCalled()
    expect(box()).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByText(/at column 11/)).toBeTruthy()
    // The field selects the problem, so it scrolls there.
    expect(box().selectionStart).toBe(10)
    expect(box().selectionEnd).toBe(13)
    // Switching to Basic keeps Query mode and the text.
    fireEvent.click(basic())
    await settle()
    expect(onApply).not.toHaveBeenCalled()
    expect(query()).toHaveAttribute('aria-pressed', 'true')
    expect(box().value).toBe('severity= AND kev=true')
  })

  it('Escape puts back the applied text', async () => {
    serve({})
    render(<Harness onApply={vi.fn()} />)
    fireEvent.click(query())
    await settle()
    fireEvent.change(box(), { target: { value: 'kev=' } })
    fireEvent.keyDown(box(), { key: 'Escape' })
    expect(box().value).toBe('practice!=compliance severity=critical state=open')
  })

  it('Ctrl+/ switches modes; the phone toggle says its state', async () => {
    serve({})
    render(<Harness onApply={vi.fn()} />)
    const toggle = () => screen.getByRole('button', { name: 'Query mode' })
    expect(toggle()).toHaveAttribute('aria-pressed', 'false')
    fireEvent.keyDown(window, { key: '/', ctrlKey: true })
    await settle()
    expect(toggle()).toHaveAttribute('aria-pressed', 'true')
    expect(box().value).toBe('practice!=compliance severity=critical state=open')
  })

  it('an fq filter is shown after the printed params, both applying', () => {
    expect(joinFilterText('state=open', 'kev=true OR epss>=0.5')).toBe(
      'state=open (kev=true OR epss>=0.5)'
    )
    expect(joinFilterText('', 'kev=true')).toBe('kev=true')
    expect(joinFilterText('state=open', null)).toBe('state=open')
  })
})
