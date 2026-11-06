/**
 * Third-party notices (About > Open-source licenses): the components a build
 * ships, with their license identifiers and texts. Same shape for the API
 * (server/pkg/notices) and the web build (scripts/third-party-notices.mjs).
 * Design: server/docs/architecture/third-party-notices.md.
 */
export interface NoticePackage {
  name: string
  version: string
  /** SPDX identifier or expression; "Unknown" when none could be determined. */
  license: string
  /** The license and NOTICE texts shipped with the package; may be empty. */
  text: string
}

export interface NoticesDocument {
  /** false for a build without a notices file (a development build). */
  generated: boolean
  component: string
  packages: NoticePackage[]
}

/** The notices file name, relative to the web server's working directory. */
export const NOTICES_FILE = 'third-party-notices.json'

/** Where each app serves the web build's notices (signed-in only). */
export const WEB_NOTICES_PATH = '/api/licenses'
export const CONSOLE_WEB_NOTICES_PATH = '/web-licenses' // under /api/v1/admin
/** Where the API serves its notices. */
export const API_NOTICES_PATH = '/api/v1/licenses'
export const ADMIN_API_NOTICES_PATH = '/licenses' // under /api/v1/admin

export function emptyNotices(component: string): NoticesDocument {
  return { generated: false, component, packages: [] }
}

function isPackage(v: unknown): v is NoticePackage {
  if (!v || typeof v !== 'object') return false
  const p = v as Record<string, unknown>
  return (
    typeof p.name === 'string' &&
    typeof p.version === 'string' &&
    typeof p.license === 'string' &&
    typeof p.text === 'string'
  )
}

/** A notices document from untrusted JSON; malformed input gives null. */
export function parseNotices(v: unknown, component: string): NoticesDocument | null {
  if (!v || typeof v !== 'object') return null
  const d = v as Record<string, unknown>
  if (!Array.isArray(d.packages)) return null
  return {
    generated: d.generated === true,
    component: typeof d.component === 'string' && d.component ? d.component : component,
    packages: d.packages.filter(isPackage),
  }
}
