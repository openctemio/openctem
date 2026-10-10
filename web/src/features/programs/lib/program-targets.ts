import type { ProgramItem } from '../api/programs-api.types'

/** The port limit of an in-scope target or entry ("8443/tcp", "80,443"); "" for none. */
export function portLimit(ports?: string, protocol?: string): string {
  if (!ports && !protocol) return ''
  if (!ports) return protocol ?? ''
  return protocol ? `${ports}/${protocol}` : ports
}

/** The limit a target carries: its ports, or the path of a path-limited URL. */
export function itemLimit(it: ProgramItem): string {
  const ports = portLimit(it.ports, it.protocol)
  if (ports) return ports
  if (it.kind === 'url' && it.pattern) {
    const m = /^[a-z]+:\/\/[^/]+(\/.*?)\*?$/i.exec(it.pattern)
    if (m && m[1] !== '/') return m[1]
  }
  return ''
}
