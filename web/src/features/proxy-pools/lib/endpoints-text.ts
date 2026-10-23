/**
 * True when a pasted proxy list holds no proxy (blank lines and comments
 * only). Shared by every place that can enable a pool: an enabled pool with
 * no proxy makes its sensors' scans fail closed, and the API refuses it.
 */
export function hasNoProxyLines(text: string): boolean {
  return text.split('\n').every((l) => l.trim() === '' || l.trim().startsWith('#'))
}
