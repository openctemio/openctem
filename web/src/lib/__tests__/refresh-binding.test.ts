import { describe, expect, it } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

import {
  REFRESH_BINDING_COOKIE,
  ensureRefreshBindingCookie,
  isRefreshBinding,
  newRefreshBinding,
  refreshBindingFromCookieHeader,
} from '@/lib/refresh-binding'

const VALID = 'a'.repeat(64)

describe('refresh client binding', () => {
  it('new bindings are 256-bit hex and differ', () => {
    const a = newRefreshBinding()
    const b = newRefreshBinding()
    expect(isRefreshBinding(a)).toBe(true)
    expect(a).not.toBe(b)
  })

  it('reads only a well-formed binding from the Cookie header', () => {
    expect(refreshBindingFromCookieHeader(null)).toBeUndefined()
    expect(refreshBindingFromCookieHeader(`x=1; ${REFRESH_BINDING_COOKIE}=${VALID}`)).toBe(VALID)
    expect(refreshBindingFromCookieHeader(`${REFRESH_BINDING_COOKIE}=short`)).toBeUndefined()
    expect(
      refreshBindingFromCookieHeader(`${REFRESH_BINDING_COOKIE}=${'Z'.repeat(64)}`)
    ).toBeUndefined()
    expect(
      refreshBindingFromCookieHeader(`other_${REFRESH_BINDING_COOKIE}=${VALID}`)
    ).toBeUndefined()
  })

  it('sets an HttpOnly cookie when the request has none', () => {
    const req = new NextRequest('https://console.example.com/findings')
    const res = NextResponse.next()
    ensureRefreshBindingCookie(req, res)
    const set = res.cookies.get(REFRESH_BINDING_COOKIE)
    expect(isRefreshBinding(set?.value)).toBe(true)
    expect(set?.httpOnly).toBe(true)
    expect(set?.path).toBe('/')
    expect(set?.sameSite).toBe('lax')
  })

  it('keeps a valid cookie and replaces a malformed one', () => {
    const kept = new NextRequest('https://console.example.com/', {
      headers: { cookie: `${REFRESH_BINDING_COOKIE}=${VALID}` },
    })
    const res1 = NextResponse.next()
    ensureRefreshBindingCookie(kept, res1)
    expect(res1.cookies.get(REFRESH_BINDING_COOKIE)).toBeUndefined()

    const bad = new NextRequest('https://console.example.com/', {
      headers: { cookie: `${REFRESH_BINDING_COOKIE}=junk` },
    })
    const res2 = NextResponse.next()
    ensureRefreshBindingCookie(bad, res2)
    expect(isRefreshBinding(res2.cookies.get(REFRESH_BINDING_COOKIE)?.value)).toBe(true)
  })
})
