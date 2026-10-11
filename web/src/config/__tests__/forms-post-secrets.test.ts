import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// A <form> without method="post" submits as GET when its JavaScript has not
// loaded (slow network, error, hydration not finished): the browser then puts
// every field, passwords included, in the URL, where proxies and access logs
// keep it. Any component with a password or secret field must post.
const ROOT = join(__dirname, '..', '..')
const SECRET =
  /type=["{][^"}]*password|type=\{show\w*\s*\?|autoComplete=["'](current|new)-password|one-time-code/

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (name === 'node_modules' || name === '__tests__') continue
    if (statSync(p).isDirectory()) walk(p, out)
    else if (p.endsWith('.tsx')) out.push(p)
  }
  return out
}

describe('forms with secret fields post', () => {
  it('every <form> in a component with a password/secret field has method="post"', () => {
    const offenders: string[] = []
    for (const file of walk(ROOT)) {
      const src = readFileSync(file, 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/^\s*\/\/.*$/gm, '')
      if (!SECRET.test(src)) continue
      for (const m of src.matchAll(/<form\b[^>]*>/gs)) {
        if (!/\bmethod=["']post["']/.test(m[0])) offenders.push(file.slice(ROOT.length + 1))
      }
    }
    expect(offenders).toEqual([])
  })
})
