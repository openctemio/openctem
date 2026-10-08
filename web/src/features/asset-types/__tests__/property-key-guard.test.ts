/**
 * Guard: asset properties are read and written only by a registry key.
 *
 * The property schema is api/configs/asset-types.yaml, generated into
 * `AssetPropertyKey` (registry.generated.ts). Code that reaches into
 * `asset.metadata.<key>` names a key by hand, and such keys drifted from the
 * registry before (the per-type pages read `os`, `cpu_cores`, `cert_issuer`
 * … that ingest never writes). Asset code reads a property through
 * `propertyValue` / `propertyStrings` (or a facts helper built on them),
 * whose key parameter is `AssetPropertyKey`, so a key outside the schema
 * does not compile. This test fails on any raw member or literal-index
 * access to `.metadata` in asset code.
 *
 * docs/architecture/asset-inventory-v2.md, "Property names".
 */
import fs from 'node:fs'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

import { ASSET_PROPERTIES } from '../registry.generated'

const SRC_ROOT = path.resolve(__dirname, '../../..')

/** Directories whose `.metadata` is an asset's properties. */
const ASSET_DIRS = [
  'features/assets',
  'features/asset-types',
  'features/asset-groups',
  'features/web-surface',
  'app/(dashboard)/(discovery)/assets',
  'app/(dashboard)/(scoping)',
]

/**
 * The per-type list pages, which predate the schema and are being replaced by
 * the registry-driven inventory (research/77). Remove each entry with its page.
 */
const LEGACY_PAGES = new Set([
  'app/(dashboard)/(discovery)/assets/apis/config.tsx',
  'app/(dashboard)/(discovery)/assets/certificates/config.tsx',
  'app/(dashboard)/(discovery)/assets/cloud-accounts/config.tsx',
  'app/(dashboard)/(discovery)/assets/cloud-resources/config.tsx',
  'app/(dashboard)/(discovery)/assets/containers/config.tsx',
  'app/(dashboard)/(discovery)/assets/databases/config.tsx',
  'app/(dashboard)/(discovery)/assets/domains/config.tsx',
  'app/(dashboard)/(discovery)/assets/hosts/config.tsx',
  'app/(dashboard)/(discovery)/assets/identity/config.tsx',
  'app/(dashboard)/(discovery)/assets/ip-addresses/config.tsx',
  'app/(dashboard)/(discovery)/assets/mobile/config.tsx',
  'app/(dashboard)/(discovery)/assets/networks/config.tsx',
  'app/(dashboard)/(discovery)/assets/repositories/config.tsx',
  'app/(dashboard)/(discovery)/assets/serverless/config.tsx',
  'app/(dashboard)/(discovery)/assets/services/config.tsx',
  'app/(dashboard)/(discovery)/assets/storage/config.tsx',
  'app/(dashboard)/(discovery)/assets/websites/config.tsx',
])

/** A member read/write (`.metadata.os`, `.metadata?.os`) or a literal index (`.metadata['os']`). */
const RAW_ACCESS = /\.metadata\??\.(?:[A-Za-z_$][\w$]*|\[\s*['"`])|\.metadata\[\s*['"`]/

function walk(dir: string, out: string[]) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(full, out)
    else if (/\.tsx?$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name)) out.push(full)
  }
}

describe('asset property keys', () => {
  it('asset code never reaches into .metadata by a hand-written key', () => {
    const files: string[] = []
    for (const d of ASSET_DIRS) {
      const full = path.join(SRC_ROOT, d)
      if (fs.existsSync(full)) walk(full, files)
    }
    const bad: string[] = []
    for (const file of files) {
      const rel = path.relative(SRC_ROOT, file).split(path.sep).join('/')
      if (LEGACY_PAGES.has(rel) || rel.includes('/__tests__/') || rel.includes('/__fixtures__/'))
        continue
      fs.readFileSync(file, 'utf8')
        .split('\n')
        .forEach((line, i) => {
          if (RAW_ACCESS.test(line)) bad.push(`${rel}:${i + 1}: ${line.trim()}`)
        })
    }
    expect(bad, 'read properties through propertyValue / propertyStrings').toEqual([])
  })

  it('the legacy list stays honest: every entry still exists', () => {
    for (const rel of LEGACY_PAGES) expect(fs.existsSync(path.join(SRC_ROOT, rel)), rel).toBe(true)
  })

  it('every schema key follows the naming convention', () => {
    for (const key of Object.keys(ASSET_PROPERTIES)) {
      expect(key, key).toMatch(/^[a-z][a-z0-9_]*$/)
    }
  })
})
