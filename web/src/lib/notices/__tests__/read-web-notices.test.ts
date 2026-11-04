/**
 * @vitest-environment node
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

import { loadWebNotices } from '../read-web-notices'
import { NOTICES_FILE, parseNotices } from '../types'

function dirWith(body?: string) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'web-notices-'))
  if (body !== undefined) fs.writeFileSync(path.join(dir, NOTICES_FILE), body)
  return dir
}

describe('loadWebNotices', () => {
  it('reads the notices file next to the server', async () => {
    const doc = await loadWebNotices(
      dirWith(
        JSON.stringify({
          generated: true,
          component: 'web',
          packages: [{ name: 'react', version: '19.2.0', license: 'MIT', text: 't' }],
        })
      )
    )
    expect(doc.generated).toBe(true)
    expect(doc.packages).toHaveLength(1)
  })

  it('gives an empty, not-generated list without a file (a development build)', async () => {
    expect(await loadWebNotices(dirWith())).toEqual({
      generated: false,
      component: 'web',
      packages: [],
    })
  })

  it('gives an empty list for a malformed file', async () => {
    expect((await loadWebNotices(dirWith('{'))).generated).toBe(false)
  })
})

describe('parseNotices', () => {
  it('drops malformed rows and rejects non-documents', () => {
    expect(parseNotices('x', 'api')).toBeNull()
    expect(parseNotices({ packages: 'x' }, 'api')).toBeNull()
    const doc = parseNotices(
      {
        generated: true,
        packages: [{ name: 'a', version: '1', license: 'MIT', text: '' }, { name: 1 }],
      },
      'api'
    )
    expect(doc).toEqual({
      generated: true,
      component: 'api',
      packages: [{ name: 'a', version: '1', license: 'MIT', text: '' }],
    })
  })
})
