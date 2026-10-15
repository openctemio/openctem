/**
 * Scrolls `el` into view inside its nearest scrolling ancestor only.
 *
 * `Element.scrollIntoView` scrolls every scrollable ancestor, including a
 * frame whose overflow is `hidden` (it cannot be scrolled by the user, but it
 * can be scrolled by script). In the phone drawer that moved the whole sheet
 * frame up, left a blank band under the body and cut the body off with no
 * way to scroll it back. This helper moves the one container a user can
 * scroll and nothing else.
 */
export function scrollIntoContainer(
  el: HTMLElement | null | undefined,
  block: 'start' | 'center' = 'start'
): void {
  if (!el) return
  const container = nearestScrollContainer(el)
  if (!container) return
  const box = container.getBoundingClientRect()
  const r = el.getBoundingClientRect()
  const delta =
    block === 'start'
      ? r.top - box.top
      : r.top + r.height / 2 - (box.top + container.clientHeight / 2)
  container.scrollTop = Math.max(0, container.scrollTop + delta)
}

/** The nearest ancestor of `el` whose content scrolls vertically (auto or scroll). */
export function nearestScrollContainer(el: HTMLElement): HTMLElement | null {
  let node = el.parentElement
  while (node && node !== document.body && node !== document.documentElement) {
    const oy = getComputedStyle(node).overflowY
    if (oy === 'auto' || oy === 'scroll' || oy === 'overlay') return node
    node = node.parentElement
  }
  return null
}
