/**
 * Production serving contract (research/29-ui-performance.md): the image runs
 * as a non-root user on a read-only root filesystem with /tmp and .next/cache
 * as the only writable paths, and responses do not advertise the framework.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import nextConfig from '../../../next.config'

const WEB = join(__dirname, '..', '..', '..')
const read = (p: string) => readFileSync(join(WEB, p), 'utf8')

describe('production serving', () => {
  it('sends no X-Powered-By header', () => {
    expect(nextConfig.poweredByHeader).toBe(false)
  })

  it('creates .next/cache for the runtime user, so it can be a tmpfs on a read-only root', () => {
    const dockerfile = read('Dockerfile')
    expect(dockerfile).toMatch(/mkdir -p \.next\/cache && chown -R nextjs:nodejs \.next/)
    expect(dockerfile).toMatch(/^USER nextjs$/m)
  })

  it.each(['../api/deploy/docker-compose.yml'])(
    '%s runs the web read-only with only /tmp and .next/cache writable',
    (file) => {
      const compose = read(file)
      expect(compose).toMatch(/read_only: true/)
      expect(compose).toMatch(/- \/tmp\n\s+- \/app\/\.next\/cache:uid=1001,gid=1001/)
      expect(compose).toMatch(/cap_drop:\n\s+- ALL/)
    }
  )
})
