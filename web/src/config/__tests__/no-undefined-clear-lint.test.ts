// @vitest-environment node
/**
 * The `x || undefined` ban in settings edit payloads (eslint.config.mjs).
 * A cleared field sent as `undefined` is dropped from the JSON body, and
 * every PATCH/PUT reads "absent" as "unchanged" (23a B16).
 */
import { describe, it, expect } from 'vitest'
import { ESLint } from 'eslint'

const eslint = new ESLint({ cwd: process.cwd() })

async function messages(code: string, filePath: string) {
  const [res] = await eslint.lintText(code, { filePath })
  return res.messages.filter((m) => m.ruleId === 'no-restricted-syntax').map((m) => m.message)
}

const BAD = `
declare const updateRole: (b: { description?: string }) => Promise<void>
declare const form: { description: string }
export async function save() {
  await updateRole({ description: form.description || undefined })
}
`

const GOOD = `
declare const updateRole: (b: { description?: string }) => Promise<void>
declare const form: { description: string }
export async function save() {
  await updateRole({ description: form.description.trim() })
}
`

describe('no `|| undefined` in settings update payloads', () => {
  it('flags the pattern in a settings feature', async () => {
    const msgs = await messages(BAD, 'src/features/access-control/components/example.tsx')
    expect(msgs.some((m) => m.includes('update payload'))).toBe(true)
  }, 60000)

  it('flags it on a settings page', async () => {
    const msgs = await messages(BAD, 'src/app/(dashboard)/settings/roles/example.tsx')
    expect(msgs.some((m) => m.includes('update payload'))).toBe(true)
  }, 60000)

  it('accepts an explicit clear', async () => {
    expect(await messages(GOOD, 'src/features/access-control/components/example.tsx')).toEqual([])
  }, 60000)
})
