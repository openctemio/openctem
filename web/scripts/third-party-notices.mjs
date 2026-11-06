#!/usr/bin/env node
// Writes the web app's third-party notices: every production package the web
// app and the platform console ship (package-lock.json entries that are not
// dev-only and are installed), with its version, license identifier and the
// license text found in node_modules. No network. The image build runs it
// (web/Dockerfile, the notices stage) and both apps serve the file read-only
// to About > Open-source licenses. Same JSON shape as the API's notices
// (server/pkg/notices). Design: server/docs/architecture/third-party-notices.md.
//
//   node scripts/third-party-notices.mjs [--root <web dir>] [--out <file>]
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

/** The file name both apps read, relative to their working directory. */
export const NOTICES_FILE = 'third-party-notices.json'

const LICENSE_FILE = /^(licen[cs]e|copying|notice)([.\-_].*)?$/i

/** A package's license and NOTICE files at its root, licenses first. */
export function readLicenseText(dir) {
  let names
  try {
    names = fs.readdirSync(dir, { withFileTypes: true })
  } catch {
    return ''
  }
  const files = names
    .filter((e) => e.isFile() && LICENSE_FILE.test(e.name))
    .map((e) => e.name)
    .sort((a, b) => {
      const na = /^notice/i.test(a)
      const nb = /^notice/i.test(b)
      if (na !== nb) return na ? 1 : -1
      return a < b ? -1 : a > b ? 1 : 0
    })
  return files
    .map((f) => fs.readFileSync(path.join(dir, f), 'utf8').trim())
    .filter(Boolean)
    .join('\n\n')
}

/** The SPDX identifier in package metadata (string, {type}, or a licenses array). */
export function licenseOf(meta) {
  const one = (l) => (typeof l === 'string' ? l : l && typeof l.type === 'string' ? l.type : '')
  const direct = one(meta?.license)
  if (direct) return direct
  if (Array.isArray(meta?.licenses)) {
    const ids = meta.licenses.map(one).filter(Boolean)
    if (ids.length === 1) return ids[0]
    if (ids.length > 1) return `(${ids.join(' OR ')})`
  }
  return ''
}

/** The package name of a lockfile key: the part after the last node_modules/. */
export function nameOfKey(key) {
  const i = key.lastIndexOf('node_modules/')
  return i < 0 ? key : key.slice(i + 'node_modules/'.length)
}

/**
 * The notices of the production packages under root (a directory holding
 * package-lock.json and node_modules). Dev-only entries and optional packages
 * that are not installed (other platforms' binaries) are left out.
 */
export function collectNotices(root) {
  const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'))
  if (!lock.packages || typeof lock.packages !== 'object') {
    throw new Error('package-lock.json has no "packages" map (lockfile v2 or later is required)')
  }
  const seen = new Set()
  const packages = []
  for (const [key, entry] of Object.entries(lock.packages)) {
    if (!key || entry.dev || entry.link || !key.includes('node_modules/')) continue
    const dir = path.join(root, key)
    let meta
    try {
      meta = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'))
    } catch {
      continue // not installed on this platform
    }
    const name = entry.name || meta.name || nameOfKey(key)
    const version = entry.version || meta.version || ''
    const id = `${name}@${version}`
    if (seen.has(id)) continue
    seen.add(id)
    packages.push({
      name,
      version,
      license: entry.license || licenseOf(meta) || 'Unknown',
      text: readLicenseText(dir),
    })
  }
  packages.sort((a, b) =>
    a.name !== b.name ? (a.name < b.name ? -1 : 1) : a.version < b.version ? -1 : 1
  )
  return { generated: true, component: 'web', packages }
}

function main(argv) {
  const arg = (flag, fallback) => {
    const i = argv.indexOf(flag)
    return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback
  }
  const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
  const root = path.resolve(arg('--root', webRoot))
  const out = path.resolve(arg('--out', path.join(root, NOTICES_FILE)))
  const doc = collectNotices(root)
  fs.writeFileSync(out, JSON.stringify(doc, null, 1) + '\n')
  console.error(`wrote ${out} (${doc.packages.length} packages)`)
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2))
}
