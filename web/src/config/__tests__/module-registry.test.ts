import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { MODULE_IDS, MODULE_REGISTRY } from '../modules.generated'
import { Module } from '../route-permissions'

/**
 * The console names modules only by ids the registry declares
 * (api/configs/modules/<id>.yaml, generated into modules.generated.ts). A
 * retired or misspelled id would hide a page for good or gate nothing
 * (RFC-064 R5): the route map once gated /remediation on a module that the
 * API did not use.
 */

const SRC = join(__dirname, '..', '..')
const ROOT = join(SRC, '..')
const PATTERNS = [
  /\bmodule: '([a-z_.]+)'/g,
  /\brequiredModule: '([a-z_.]+)'/g,
  /\buseModuleEnabled\('([a-z_.]+)'\)/g,
  /\buseHasModule\('([a-z_.]+)'\)/g,
]

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) {
      if (name === '__tests__' || name === 'generated') continue
      sourceFiles(path, out)
    } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name)) {
      out.push(path)
    }
  }
  return out
}

describe('module registry', () => {
  it('declares unique ids', () => {
    expect(MODULE_IDS.size).toBe(MODULE_REGISTRY.length)
  })

  it('backs every Module constant of the route map', () => {
    const unknown = Object.entries(Module).filter(([, id]) => !MODULE_IDS.has(id))
    expect(unknown).toEqual([])
  })

  it('backs every module id the console names', () => {
    const unknown: string[] = []
    let seen = 0
    for (const file of sourceFiles(SRC)) {
      const text = readFileSync(file, 'utf8')
      for (const re of PATTERNS) {
        for (const m of text.matchAll(re)) {
          seen++
          if (!MODULE_IDS.has(m[1])) {
            unknown.push(`${relative(ROOT, file).split(sep).join('/')}: ${m[1]}`)
          }
        }
      }
    }
    expect(seen).toBeGreaterThan(50)
    expect(unknown).toEqual([])
  })
})
