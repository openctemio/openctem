/**
 * Server side: the web build's third-party notices, read once from the fixed
 * file the image build writes next to the server (web/Dockerfile, notices
 * stage). Nothing in a request chooses the file. A build without it (next dev)
 * gives an empty list with generated=false, never an error.
 */
import { readFile } from 'node:fs/promises'
import path from 'node:path'

import { NOTICES_FILE, emptyNotices, parseNotices, type NoticesDocument } from './types'

/** A real notices file is a few MiB; anything far larger is not one. */
const MAX_BYTES = 32 * 1024 * 1024

let cached: Promise<NoticesDocument> | undefined

export async function loadWebNotices(dir: string = process.cwd()): Promise<NoticesDocument> {
  try {
    const raw = await readFile(path.join(dir, NOTICES_FILE), 'utf8')
    if (raw.length > MAX_BYTES) return emptyNotices('web')
    const doc = parseNotices(JSON.parse(raw), 'web')
    return doc ? { ...doc, generated: true } : emptyNotices('web')
  } catch {
    return emptyNotices('web')
  }
}

/** The notices of this server, read on first use. */
export function readWebNotices(): Promise<NoticesDocument> {
  cached ??= loadWebNotices()
  return cached
}

/** Test hook. */
export function resetWebNoticesCache(): void {
  cached = undefined
}
