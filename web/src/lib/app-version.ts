/**
 * Build identity: what Help > About shows for the web app and the API.
 *
 * The rule (api/docs/rfcs/RFC-037 §3.2): every component reports version,
 * commit and channel. channel is "release" for a vX.Y.Z tag, "rc" for any
 * other pre-release tag, "dev" otherwise; a dev version is
 * "<highest vX.Y.Z tag>-dev+<short sha>".
 *
 * Release images bake the UI's version and commit in at build time
 * (docker-publish.yml passes NEXT_PUBLIC_APP_VERSION and NEXT_PUBLIC_APP_COMMIT
 * as build args). Other builds have neither; the server route
 * /api/version then derives "<highest tag>-dev+<commit>" from the checkout's git
 * metadata (src/lib/version/web-build-info.ts), never package.json's
 * "version", which is not bumped on release.
 *
 * The reads are literal `process.env.NEXT_PUBLIC_*` so Next inlines them.
 */
export interface AppVersion {
  /** e.g. "v0.9.0"; undefined outside a release build. */
  version?: string
  /** Short commit SHA; undefined when the build did not record it. */
  commit?: string
}

/** Same length the API reports (api/pkg/version). */
export const SHORT_COMMIT_LENGTH = 8

export function getAppVersion(): AppVersion {
  const version = process.env.NEXT_PUBLIC_APP_VERSION?.trim() || undefined
  const commit =
    process.env.NEXT_PUBLIC_APP_COMMIT?.trim().slice(0, SHORT_COMMIT_LENGTH) || undefined
  return { version, commit }
}

export type BuildChannel = 'release' | 'rc' | 'dev'

/** The shape of GET /api/version (web app) and GET /api/v1/version (API). */
export interface BuildInfo {
  version: string
  commit: string
  channel: BuildChannel
  build_time?: string
}

/** Reported when nothing names a version or commit. */
export const DEV_VERSION = 'dev'
export const UNKNOWN_COMMIT = 'unknown'

/** A tag-shaped version: v1.2.3[-prerelease][+build]; group 1 is the pre-release. */
const TAG_VERSION = /^v?\d+\.\d+\.\d+(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/

/** Same classification as the API (api/pkg/version channelOf). */
export function channelOf(version: string): BuildChannel {
  const m = TAG_VERSION.exec(version)
  if (!m) return 'dev'
  const pre = m[1]
  if (!pre) return 'release'
  return pre.startsWith('dev') ? 'dev' : 'rc'
}

/** "<tag>-dev+<short commit>" ("v0.0.0" before the first tag). */
export function devBuildVersion(tag: string | undefined, commit: string | undefined): string {
  const base = `${tag || 'v0.0.0'}-dev`
  const c = shortCommit(commit)
  return c === UNKNOWN_COMMIT ? base : `${base}+${c}`
}

/** Older API builds answered "development" for what is now "dev". */
function parseChannel(value: unknown, version: string): BuildChannel {
  if (value === 'release' || value === 'rc' || value === 'dev') return value
  if (value === 'development') return 'dev'
  return channelOf(version)
}

export function shortCommit(commit: string | undefined): string {
  const c = commit?.trim()
  if (!c) return UNKNOWN_COMMIT
  return /^[0-9a-f]+$/i.test(c) ? c.slice(0, SHORT_COMMIT_LENGTH).toLowerCase() : c
}

/** Narrows an untrusted JSON body to BuildInfo, or null. */
export function parseBuildInfo(data: unknown): BuildInfo | null {
  if (!data || typeof data !== 'object') return null
  const d = data as Record<string, unknown>
  if (typeof d.version !== 'string' || !d.version) return null
  const commit = typeof d.commit === 'string' ? d.commit : undefined
  const channel = parseChannel(d.channel, d.version)
  return {
    version: d.version,
    commit: shortCommit(commit),
    channel,
    build_time: typeof d.build_time === 'string' && d.build_time ? d.build_time : undefined,
  }
}
