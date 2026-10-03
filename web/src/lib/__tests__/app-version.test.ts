import { describe, expect, it } from 'vitest'

import { channelOf, devBuildVersion, parseBuildInfo } from '@/lib/app-version'

// The same rule as the API's pkg/version (api/docs/rfcs/RFC-037 §3.2).
describe('channelOf', () => {
  it.each([
    ['v0.9.0', 'release'],
    ['0.9.0', 'release'],
    ['v1.2.3-rc.1', 'rc'],
    ['v0.9.0-staging', 'rc'],
    ['v0.8.0-dev', 'dev'],
    ['v0.8.0-dev+4d2f4b02', 'dev'],
    ['v0.8.0-devel', 'dev'],
    ['dev', 'dev'],
    ['', 'dev'],
    ['main', 'dev'],
  ])('%s is %s', (version, channel) => {
    expect(channelOf(version)).toBe(channel)
  })
})

describe('devBuildVersion', () => {
  it('is "<tag>-dev+<short commit>"', () => {
    expect(devBuildVersion('v0.8.0', '4d2f4b02aa11bb22cc33dd44ee55ff6677889900')).toBe(
      'v0.8.0-dev+4d2f4b02'
    )
  })
  it('drops an unknown commit and starts from v0.0.0 before the first tag', () => {
    expect(devBuildVersion('v0.8.0', undefined)).toBe('v0.8.0-dev')
    expect(devBuildVersion(undefined, 'ABCDEF1234')).toBe('v0.0.0-dev+abcdef12')
  })
})

describe('parseBuildInfo', () => {
  it('keeps the three channels', () => {
    for (const channel of ['release', 'rc', 'dev'] as const) {
      expect(parseBuildInfo({ version: 'v0.9.0', commit: 'abc', channel })?.channel).toBe(channel)
    }
  })
  it('reads "development" from an API older than RFC-037 as dev', () => {
    expect(
      parseBuildInfo({ version: 'v0.8.0-dev', commit: '4d2f4b02', channel: 'development' })
    ).toEqual({ version: 'v0.8.0-dev', commit: '4d2f4b02', channel: 'dev', build_time: undefined })
  })
  it('derives a missing or unknown channel from the version', () => {
    expect(parseBuildInfo({ version: 'v0.9.0-rc.2' })?.channel).toBe('rc')
    expect(parseBuildInfo({ version: 'v0.9.0', channel: 'beta' })?.channel).toBe('release')
  })
  it('refuses a body without a version', () => {
    expect(parseBuildInfo({ commit: 'abc' })).toBeNull()
    expect(parseBuildInfo(null)).toBeNull()
  })
})
