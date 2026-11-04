// Tests for scripts/third-party-notices.mjs on a tiny fixture tree (no network).
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { collectNotices, licenseOf, nameOfKey, readLicenseText } from './third-party-notices.mjs'

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notices-'))
  const write = (rel, body) => {
    const p = path.join(root, rel)
    fs.mkdirSync(path.dirname(p), { recursive: true })
    fs.writeFileSync(p, typeof body === 'string' ? body : JSON.stringify(body))
  }
  write('package-lock.json', {
    lockfileVersion: 3,
    packages: {
      '': { name: 'web', dependencies: { a: '1' } },
      'node_modules/a': { version: '1.0.0', license: 'MIT' },
      'node_modules/@scope/b': { version: '2.0.0' },
      'node_modules/a/node_modules/c': { version: '0.1.0', license: 'Apache-2.0' },
      'node_modules/dev-only': { version: '9.9.9', license: 'MIT', dev: true },
      'node_modules/other-platform': { version: '1.0.0', license: 'MIT', optional: true },
    },
  })
  write('node_modules/a/package.json', { name: 'a', version: '1.0.0', license: 'MIT' })
  write('node_modules/a/LICENSE', 'MIT License\nCopyright (c) a\n')
  write('node_modules/@scope/b/package.json', {
    name: '@scope/b',
    version: '2.0.0',
    licenses: [{ type: 'MIT' }, { type: 'Apache-2.0' }],
  })
  write('node_modules/@scope/b/NOTICE', 'b notice')
  write('node_modules/@scope/b/LICENSE.md', 'b license')
  write('node_modules/a/node_modules/c/package.json', { name: 'c', version: '0.1.0' })
  write('node_modules/dev-only/package.json', { name: 'dev-only', version: '9.9.9' })
  return root
}

describe('third-party notices', () => {
  it('lists the installed production packages with their license texts', () => {
    const doc = collectNotices(fixture())
    expect(doc.generated).toBe(true)
    expect(doc.component).toBe('web')
    expect(doc.packages.map((p) => `${p.name}@${p.version} ${p.license}`)).toEqual([
      '@scope/b@2.0.0 (MIT OR Apache-2.0)',
      'a@1.0.0 MIT',
      'c@0.1.0 Apache-2.0',
    ])
    const b = doc.packages.find((p) => p.name === '@scope/b')
    // The license first, then the NOTICE file.
    expect(b.text).toBe('b license\n\nb notice')
    expect(doc.packages.find((p) => p.name === 'c').text).toBe('')
  })

  it('reads license metadata in every form', () => {
    expect(licenseOf({ license: 'ISC' })).toBe('ISC')
    expect(licenseOf({ license: { type: 'BSD-3-Clause' } })).toBe('BSD-3-Clause')
    expect(licenseOf({ licenses: [{ type: 'MIT' }] })).toBe('MIT')
    expect(licenseOf({})).toBe('')
  })

  it('names packages from lockfile keys', () => {
    expect(nameOfKey('node_modules/@scope/b')).toBe('@scope/b')
    expect(nameOfKey('node_modules/a/node_modules/c')).toBe('c')
  })

  it('gives no text for a directory that is not there', () => {
    expect(readLicenseText('/nonexistent/notices-dir')).toBe('')
  })
})
