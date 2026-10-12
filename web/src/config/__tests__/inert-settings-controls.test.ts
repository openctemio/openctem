/**
 * No settings control without a consumer (owner decisions B5, B6; settings
 * audit 23a B5, B9, B10, B22, U3). Each control below saved a value that
 * nothing reads. They stay hidden until a server-side consumer exists; this
 * fails if one comes back.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = join(__dirname, '..', '..')
const read = (rel: string) => readFileSync(join(SRC, rel), 'utf8')

const HIDDEN: Array<{ file: string; text: string; why: string }> = [
  {
    file: 'features/organization/components/organization-settings.tsx',
    text: '<Label>Session timeout</Label>',
    why: 'organization session timeout is not enforced yet (B5)',
  },
  {
    file: 'features/organization/components/organization-settings.tsx',
    text: 'htmlFor="industry"',
    why: 'organization industry has no reader (B6)',
  },
  {
    file: 'features/organization/components/organization-settings.tsx',
    text: 'Default language',
    why: 'organization language and timezone have no reader (B6)',
  },
  {
    file: 'app/(dashboard)/account/preferences/page.tsx',
    text: 'htmlFor="language"',
    why: 'a second language picker that drove nothing (the user menu picks the language)',
  },
  {
    file: 'app/(dashboard)/account/notifications/page.tsx',
    text: 'Email digest',
    why: 'no digest sender exists',
  },
  {
    file: 'app/(dashboard)/account/notifications/page.tsx',
    text: 'Desktop notifications',
    why: 'no desktop notifications are sent',
  },
  {
    file: 'features/asset-lifecycle/components/lifecycle-settings-form.tsx',
    text: 'Manual reactivation grace',
    why: 'nothing reads manual_reactivation_grace_days',
  },
]

describe('inert settings controls stay hidden', () => {
  for (const h of HIDDEN) {
    it(`${h.file}: ${h.why}`, () => {
      expect(read(h.file)).not.toContain(h.text)
    })
  }
})
