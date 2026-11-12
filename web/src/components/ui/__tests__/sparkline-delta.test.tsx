import axe from 'axe-core'
import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Delta } from '../delta'
import { Sparkline } from '../sparkline'

async function violations(root: HTMLElement) {
  const res = await axe.run(root, { rules: { 'color-contrast': { enabled: false } } })
  return res.violations.map((v) => `${v.id}: ${v.help}`)
}

describe('Sparkline', () => {
  it('is one image named by its text summary, with no other accessible text', async () => {
    const { container } = render(
      <Sparkline values={[3, 5, 4, 9]} summary="Open findings rose from 3 to 9 in 4 days" />
    )
    expect(
      screen.getByRole('img', { name: 'Open findings rose from 3 to 9 in 4 days' })
    ).toBeTruthy()
    expect(container.querySelector('path')).not.toBeNull()
    expect(await violations(container)).toEqual([])
  })

  it('draws nothing when there is no sample, and skips gaps in a line instead of reading them as 0', () => {
    const { container, rerender } = render(<Sparkline values={[null, undefined]} summary="none" />)
    expect(container).toBeEmptyDOMElement()
    rerender(<Sparkline values={[2, null, 4]} summary="gap" />)
    const d = container.querySelector('path')!.getAttribute('d')!
    expect(d.split('L')).toHaveLength(2) // two real points, one segment
  })

  it('bars: one rect per slot, a warning bar flagged and titled, a gap a hairline', async () => {
    const { container } = render(
      <Sparkline
        variant="bars"
        values={[10, null, 40]}
        warn={[false, false, true]}
        titles={['a', 'b', 'late slot']}
        reference={20}
        summary="3 slots, 1 late"
      />
    )
    expect(container.querySelectorAll('rect')).toHaveLength(3)
    expect(container.querySelectorAll('rect[data-late]')).toHaveLength(1)
    expect(container.querySelector('rect[data-late] title')?.textContent).toBe('late slot')
    expect(container.querySelectorAll('rect')[1].getAttribute('height')).toBe('1')
    expect(container.querySelector('line')).not.toBeNull()
    expect(await violations(container)).toEqual([])
  })
})

describe('Delta', () => {
  it('colours by outcome, not direction: a fall can be better, and the verdict is spoken', async () => {
    const { container } = render(
      <Delta delta={-12} text="-12" tone="better" against="vs previous period" verdict="better" />
    )
    const el = container.querySelector('[data-slot="delta"]')!
    expect(el.getAttribute('data-tone')).toBe('better')
    expect(el.className).toContain('text-good')
    expect(el.textContent).toContain('-12')
    expect(el.textContent).toContain('vs previous period')
    expect(el.querySelector('.sr-only')?.textContent).toBe('(better)')
    expect(await violations(container)).toEqual([])
  })

  it('worse uses the bad token and neutral stays muted', () => {
    const { container } = render(
      <>
        <Delta delta={4} text="+4" tone="worse" />
        <Delta delta={0} text="0" tone="flat" />
      </>
    )
    const [a, b] = Array.from(container.querySelectorAll('[data-slot="delta"]'))
    expect(a.className).toContain('text-bad')
    expect(b.className).toContain('text-muted-foreground')
  })
})
