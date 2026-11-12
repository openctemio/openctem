import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import {
  TENANT_CHANGED_EVENT,
  TenantChangedError,
  endTenantEpoch,
  noteRendered,
  onTenantChangedElsewhere,
  renderedUnderOtherOrg,
  resetTenantEpochForTests,
  setActiveTenantId,
  tenantChangedTo,
  tenantRequestSignal,
} from '@/lib/tenant-epoch'
import { coalesceGet } from '@/lib/api/request-dedupe'
import { env } from '@/lib/env'

function setTenantCookie(id: string | null) {
  document.cookie =
    id === null
      ? `${env.cookies.tenant}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`
      : `${env.cookies.tenant}=${encodeURIComponent(JSON.stringify({ id, slug: id, role: 'member' }))}; path=/`
}

beforeEach(() => {
  resetTenantEpochForTests()
  setTenantCookie(null)
})
afterEach(() => setTenantCookie(null))

describe('request guard', () => {
  it('lets requests through while the session is the tab organization', () => {
    setActiveTenantId('org-a')
    setTenantCookie('org-a')
    expect(tenantChangedTo()).toBeNull()
    expect(tenantRequestSignal('GET')).toBeInstanceOf(AbortSignal)
    expect(tenantRequestSignal('POST')).toBeUndefined()
  })

  it('sends nothing once another tab moved the session to another organization', () => {
    setActiveTenantId('org-a')
    setTenantCookie('org-b')
    const seen = vi.fn()
    window.addEventListener(TENANT_CHANGED_EVENT, seen)
    // A bulk write built from organization A's selection is refused here.
    expect(() => tenantRequestSignal('POST')).toThrow(TenantChangedError)
    expect(() => tenantRequestSignal('GET')).toThrow(TenantChangedError)
    expect(seen).toHaveBeenCalledTimes(2)
    window.removeEventListener(TENANT_CHANGED_EVENT, seen)
  })

  it('stands down without a known tab organization or without a cookie', () => {
    setTenantCookie('org-b')
    expect(() => tenantRequestSignal('GET')).not.toThrow()
    setActiveTenantId('org-a')
    setTenantCookie(null)
    expect(() => tenantRequestSignal('GET')).not.toThrow()
  })
})

describe('endTenantEpoch', () => {
  it('aborts the reads of the ending epoch, not the next ones', () => {
    const before = tenantRequestSignal('GET')!
    endTenantEpoch()
    expect(before.aborted).toBe(true)
    expect(tenantRequestSignal('GET')!.aborted).toBe(false)
  })

  it('a read of the new organization never joins one the old organization started', async () => {
    let resolveOld: (v: string) => void = () => {}
    const old = coalesceGet('/api/v1/findings', () => new Promise<string>((r) => (resolveOld = r)))
    endTenantEpoch()
    const fresh = coalesceGet('/api/v1/findings', async () => 'org-b rows')
    resolveOld('org-a rows')
    await expect(old).resolves.toBe('org-a rows')
    await expect(fresh).resolves.toBe('org-b rows')
  })
})

describe('onTenantChangedElsewhere', () => {
  it('fires when the tab comes back with another organization in the cookie', () => {
    setActiveTenantId('org-a')
    const onChange = vi.fn()
    const off = onTenantChangedElsewhere(onChange)
    window.dispatchEvent(new Event('focus'))
    expect(onChange).not.toHaveBeenCalled()
    setTenantCookie('org-b')
    window.dispatchEvent(new Event('focus'))
    expect(onChange).toHaveBeenCalledTimes(1)
    window.dispatchEvent(new Event(TENANT_CHANGED_EVENT))
    expect(onChange).toHaveBeenCalledTimes(2)
    off()
    window.dispatchEvent(new Event('focus'))
    expect(onChange).toHaveBeenCalledTimes(2)
  })
})

describe('addresses per organization', () => {
  it('knows an address last shown in another organization', () => {
    noteRendered('/findings?page=5', 'org-a')
    noteRendered('/findings', 'org-a')
    noteRendered('/findings', 'org-b')
    expect(renderedUnderOtherOrg('/findings?page=5', 'org-b')).toBe(true)
    expect(renderedUnderOtherOrg('/findings?page=5', 'org-a')).toBe(false)
    expect(renderedUnderOtherOrg('/findings', 'org-b')).toBe(false)
    expect(renderedUnderOtherOrg('/never-seen', 'org-b')).toBe(false)
  })

  it('survives a new document of the same tab (sessionStorage) and stays bounded', () => {
    for (let i = 0; i < 260; i++) noteRendered(`/findings?page=${i}`, 'org-a')
    const stored = JSON.parse(sessionStorage.getItem('openctem:org-visits') ?? '{}')
    expect(Object.keys(stored).length).toBe(200)
    expect(stored['/findings?page=259']).toBe('org-a')
    expect(stored['/findings?page=0']).toBeUndefined()
  })
})

describe('one data cache per organization epoch', () => {
  const SRC = join(process.cwd(), 'src')
  const CONSOLE = join(process.cwd(), 'console', 'src')

  function sources(dir: string, out: string[] = []): string[] {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name)
      if (statSync(full).isDirectory()) {
        if (name === '__tests__' || name === 'node_modules') continue
        sources(full, out)
      } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name)) {
        out.push(full)
      }
    }
    return out
  }

  it("no code reaches SWR's default cache with a global mutate", () => {
    const offenders: string[] = []
    for (const file of [...sources(SRC), ...sources(CONSOLE)]) {
      const rel = relative(process.cwd(), file)
      if (rel === join('src', 'lib', 'swr-mutate.ts')) continue
      const text = readFileSync(file, 'utf8')
      if (
        /import\(\s*['"]swr['"]\s*\)/.test(text) ||
        /import[^;]*\{[^}]*\b(mutate|preload)\b[^}]*\}\s*from\s*['"]swr['"]/.test(text)
      ) {
        offenders.push(rel)
      }
    }
    expect(offenders).toEqual([])
  })
})
