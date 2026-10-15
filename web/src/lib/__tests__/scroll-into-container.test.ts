import { afterEach, describe, expect, it } from 'vitest'

import { nearestScrollContainer, scrollIntoContainer } from '@/lib/scroll-into-container'

function box(el: HTMLElement, top: number, height: number) {
  el.getBoundingClientRect = () =>
    ({ top, height, bottom: top + height, left: 0, right: 0, width: 0, x: 0, y: top }) as DOMRect
}

/** frame (overflow hidden) > body (overflow auto) > item, as in the phone drawer. */
function drawer() {
  const frame = document.createElement('div')
  frame.style.overflowY = 'hidden'
  const body = document.createElement('div')
  body.style.overflowY = 'auto'
  Object.defineProperty(body, 'clientHeight', { value: 500 })
  const item = document.createElement('div')
  body.appendChild(item)
  frame.appendChild(body)
  document.body.appendChild(frame)
  return { frame, body, item }
}

afterEach(() => {
  document.body.innerHTML = ''
})

describe('scrollIntoContainer', () => {
  it('scrolls only the nearest scrolling ancestor, never the frame around it', () => {
    const { frame, body, item } = drawer()
    box(body, 260, 500)
    box(item, 700, 300)
    body.scrollTop = 100
    scrollIntoContainer(item, 'start')
    expect(body.scrollTop).toBe(540)
    expect(frame.scrollTop).toBe(0)
  })

  it('centres the element in the container', () => {
    const { body, item } = drawer()
    box(body, 0, 500)
    box(item, 900, 100)
    scrollIntoContainer(item, 'center')
    // item centre 950 - container centre 250
    expect(body.scrollTop).toBe(700)
  })

  it('never scrolls above the top and ignores a missing element', () => {
    const { body, item } = drawer()
    box(body, 300, 500)
    box(item, 0, 50)
    scrollIntoContainer(item, 'start')
    expect(body.scrollTop).toBe(0)
    expect(() => scrollIntoContainer(null)).not.toThrow()
  })

  it('finds no container when no ancestor scrolls', () => {
    const el = document.createElement('div')
    document.body.appendChild(el)
    expect(nearestScrollContainer(el)).toBeNull()
  })
})
