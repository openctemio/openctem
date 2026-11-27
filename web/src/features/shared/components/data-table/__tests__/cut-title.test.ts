import { describe, expect, it } from 'vitest'
import { isTextCut, syncCutTitle } from '../cut-title'

/** jsdom lays nothing out: give a box the sizes a browser would. */
function sized(el: HTMLElement, scroll: number, client: number) {
  Object.defineProperty(el, 'scrollWidth', { configurable: true, value: scroll })
  Object.defineProperty(el, 'clientWidth', { configurable: true, value: client })
  return el
}

function nameCell(text: string, scroll: number, client: number) {
  const td = document.createElement('td')
  const p = document.createElement('p')
  p.className = 'truncate'
  p.textContent = text
  sized(p, scroll, client)
  td.appendChild(p)
  return td
}

describe('cut name title', () => {
  it('a name cut by its ellipsis gets its full text as the title, and loses it once it fits', () => {
    const td = nameCell('payments-gateway.internal.example.com', 320, 120)
    expect(isTextCut(td)).toBe(true)
    syncCutTitle(td, isTextCut(td))
    expect(td.title).toBe('payments-gateway.internal.example.com')
    sized(td.querySelector('p')!, 120, 120)
    syncCutTitle(td, isTextCut(td))
    expect(td.hasAttribute('title')).toBe(false)
  })

  it('keeps a title the page set itself', () => {
    const td = nameCell('payments-gateway', 320, 120)
    td.title = 'Payments gateway (production)'
    syncCutTitle(td, true)
    syncCutTitle(td, false)
    expect(td.title).toBe('Payments gateway (production)')
  })

  it('a link a parent cuts by its style (the phone card title) is a cut', () => {
    const title = document.createElement('div')
    const a = sized(document.createElement('a'), 320, 120)
    a.style.textOverflow = 'ellipsis'
    a.textContent = 'Payments platform external perimeter'
    title.appendChild(a)
    expect(isTextCut(title)).toBe(true)
  })

  it('a box with no ellipsis or clamp is not a cut', () => {
    const td = document.createElement('td')
    const span = sized(document.createElement('span'), 320, 120)
    span.textContent = 'scrolls on its own'
    td.appendChild(span)
    expect(isTextCut(td)).toBe(false)
  })
})
