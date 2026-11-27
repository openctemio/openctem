/**
 * Whether an element draws anything on screen: some leaf element (or icon) of
 * it has a box with an area. An icon counts by its own box: the shapes inside
 * it are often a line with no area (an icon-only Add filter draws only such
 * lines), which is not "nothing".
 */
export function drawsSomething(group: HTMLElement): boolean {
  return Array.from(group.querySelectorAll<Element>('*')).some((el) => {
    const icon = el.closest('svg')
    if (icon ? icon !== el : el.children.length > 0) return false
    return Array.from(el.getClientRects()).some((r) => r.width > 0 && r.height > 0)
  })
}
