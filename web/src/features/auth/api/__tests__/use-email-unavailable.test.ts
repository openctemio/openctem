import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'

// The SWR key the hook asks for: null means no request to /auth/providers.
let keys: unknown[] = []
let providers: { email_delivery?: boolean } | undefined
vi.mock('swr', () => ({
  default: (key: unknown) => {
    keys.push(key)
    return { data: key ? providers : undefined }
  },
}))
let bootstrap: { isLoading: boolean; data: { email_delivery?: boolean } | null } | null = null
vi.mock('@/context/bootstrap-provider', () => ({ useBootstrapContextOptional: () => bootstrap }))

import { useEmailUnavailable } from '../use-auth-providers'

const run = () => renderHook(() => useEmailUnavailable()).result.current

describe('useEmailUnavailable', () => {
  beforeEach(() => {
    keys = []
    providers = undefined
    bootstrap = null
  })

  it('inside the app shell, reads the flag from the session bootstrap and never asks /auth/providers', () => {
    bootstrap = { isLoading: false, data: { email_delivery: false } }
    expect(run()).toBe(true)
    bootstrap = { isLoading: false, data: { email_delivery: true } }
    expect(run()).toBe(false)
    expect(keys.every((k) => k === null)).toBe(true)
  })

  it('waits for the bootstrap instead of asking in parallel', () => {
    bootstrap = { isLoading: true, data: null }
    expect(run()).toBe(false)
    expect(keys).toEqual([null])
  })

  it('asks /auth/providers when the bootstrap does not carry the flag', () => {
    bootstrap = { isLoading: false, data: {} }
    providers = { email_delivery: false }
    expect(run()).toBe(true)
    expect(keys).toEqual(['/api/v1/auth/providers'])
  })

  it('on the auth pages (no app shell), asks /auth/providers', () => {
    providers = { email_delivery: false }
    expect(run()).toBe(true)
    providers = { email_delivery: true }
    expect(run()).toBe(false)
    providers = undefined
    expect(run()).toBe(false)
    expect(keys.every((k) => k === '/api/v1/auth/providers')).toBe(true)
  })
})
