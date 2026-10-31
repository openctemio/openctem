import { describe, expect, it, vi, afterEach } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import { SettleGroup, SettleSignal, useSettleSignal } from '../settle-group'

function Block({ loading, label }: { loading: boolean; label: string }) {
  useSettleSignal(loading)
  return <p>{loading ? `${label} loading` : label}</p>
}

const contentHidden = () =>
  (document.querySelector('[data-slot="settle-group"]') as HTMLElement).hidden

afterEach(() => vi.useRealTimers())

describe('SettleGroup', () => {
  it('shows the content at once when no block is loading', () => {
    render(
      <SettleGroup fallback={<span>skeleton</span>}>
        <Block loading={false} label="band" />
      </SettleGroup>
    )
    expect(screen.queryByText('skeleton')).toBeNull()
    expect(contentHidden()).toBe(false)
  })

  it('keeps the skeleton until every block answered, then reveals in one step', () => {
    const { rerender } = render(
      <SettleGroup fallback={<span>skeleton</span>}>
        <Block loading label="band" />
        <Block loading={false} label="panel" />
      </SettleGroup>
    )
    // The blocks are mounted (their requests run) but hidden.
    expect(screen.getByText('skeleton')).toBeTruthy()
    expect(contentHidden()).toBe(true)
    expect(screen.getByText('band loading')).toBeTruthy()

    rerender(
      <SettleGroup fallback={<span>skeleton</span>}>
        <Block loading={false} label="band" />
        <Block loading={false} label="panel" />
      </SettleGroup>
    )
    expect(screen.queryByText('skeleton')).toBeNull()
    expect(contentHidden()).toBe(false)
  })

  it('stops waiting for a slow block after maxWaitMs', () => {
    vi.useFakeTimers()
    render(
      <SettleGroup fallback={<span>skeleton</span>} maxWaitMs={500}>
        <Block loading label="band" />
      </SettleGroup>
    )
    expect(contentHidden()).toBe(true)
    act(() => {
      vi.advanceTimersByTime(500)
    })
    expect(contentHidden()).toBe(false)
    expect(screen.getByText('band loading')).toBeTruthy()
  })

  it('never hides the content again once revealed', () => {
    const tree = (loading: boolean) => (
      <SettleGroup fallback={<span>skeleton</span>}>
        <Block loading={loading} label="band" />
      </SettleGroup>
    )
    const { rerender } = render(tree(false))
    rerender(tree(true))
    expect(contentHidden()).toBe(false)
    expect(screen.queryByText('skeleton')).toBeNull()
  })

  it('does nothing outside a group', () => {
    render(<Block loading label="band" />)
    expect(screen.getByText('band loading')).toBeTruthy()
  })

  it('lays its blocks out as direct children of the page once shown', () => {
    render(
      <SettleGroup fallback={<span>skeleton</span>}>
        <Block loading={false} label="band" />
      </SettleGroup>
    )
    expect(document.querySelector('[data-slot="settle-group"]')).toHaveClass('contents')
  })

  it('SettleSignal holds the group for data the page loads itself', () => {
    const tree = (pending: boolean) => (
      <SettleGroup fallback={<span>skeleton</span>}>
        <SettleSignal pending={pending} />
        <p>page</p>
      </SettleGroup>
    )
    const { rerender } = render(tree(true))
    expect(contentHidden()).toBe(true)
    rerender(tree(false))
    expect(contentHidden()).toBe(false)
  })
})
