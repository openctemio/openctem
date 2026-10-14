/**
 * Shortens a string from the middle so both the start and the end stay
 * visible: "src/main/java/…/OrderRepositoryImpl.java:42". The end gets the
 * larger share, since that is where paths and URLs differ.
 */
export function middleEllipsis(value: string, max: number): string {
  const chars = Array.from(value)
  if (max < 5 || chars.length <= max) return value
  const keep = max - 1
  const head = Math.ceil(keep * 0.35)
  const tail = keep - head
  return `${chars.slice(0, head).join('')}…${chars.slice(chars.length - tail).join('')}`
}
