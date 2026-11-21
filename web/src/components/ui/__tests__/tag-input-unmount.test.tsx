import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, fireEvent } from '@testing-library/react'
import { TagInput } from '../tag-input'

describe('TagInput blur timer', () => {
  afterEach(() => vi.useRealTimers())

  it('clears the pending blur timer when unmounted inside the 150 ms window', () => {
    vi.useFakeTimers()
    const { container, unmount } = render(
      <TagInput value={[]} onChange={() => {}} suggestions={['a']} />
    )
    const input = container.querySelector('input') as HTMLInputElement
    fireEvent.focus(input)
    fireEvent.blur(input)
    expect(vi.getTimerCount()).toBe(1)
    unmount()
    expect(vi.getTimerCount()).toBe(0)
    expect(() => vi.advanceTimersByTime(200)).not.toThrow()
  })
})
