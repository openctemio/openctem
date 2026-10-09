/**
 * A group member row opens the asset it lists. The rows used to link to
 * per-type routes (`/assets/domains/{id}`, `/assets/hosts/{id}`, ...) that do
 * not exist, so every click 404'd. They now open the generic `/assets/{id}`
 * page, which renders any asset type.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { groupMemberHref } from '@/features/asset-groups/lib/member-link'
import { ASSET_TYPE_CLASSES } from '@/features/asset-types/registry.generated'
import AssetDetailPage from '../../[id]/page'

const ID = '0b9f6c3e-1111-4222-8333-944455556666'
const APP = join(process.cwd(), 'src', 'app')
const ASSETS_DIR = join(APP, '(dashboard)', '(discovery)', 'assets')

const replace = vi.fn()
let current: Record<string, unknown> | null = null

vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace, push: vi.fn(), back: vi.fn() }),
  useParams: () => ({ id: ID }),
  usePathname: () => `/assets/${ID}`,
}))
// The detail page's own data sections (identity, attribution, ...) fetch on
// their own; stub every `*Section(s)` export so a section added later does not
// need this test to change. The page shell under test stays real.
// The repository workspace fetches its own data; a stub shows it rendered.
vi.mock('@/features/repositories/components/repository-workspace', () => ({
  RepositoryWorkspace: ({ repositoryId }: { repositoryId: string }) => (
    <div>repository workspace {repositoryId}</div>
  ),
}))
vi.mock('@/features/scan-windows', () => ({ AssetScanWindowCard: () => null }))
vi.mock('@/features/assets', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>()
  const sections = Object.keys(actual)
    .filter((k) => /^Asset\w*Sections?$/.test(k))
    .map((k) => [k, () => null])
  return {
    ...actual,
    ...Object.fromEntries(sections),
    useAsset: () => ({ asset: current, isLoading: false, error: null }),
  }
})

/**
 * The page file Next.js serves for a URL path: route groups are transparent,
 * and at each level a static segment wins over a dynamic `[param]` one.
 */
function resolvePage(url: string): string | null {
  function walk(dir: string, rest: string[]): string | null {
    if (rest.length === 0) {
      const page = join(dir, 'page.tsx')
      if (existsSync(page)) return page
    }
    const dirs = readdirSync(dir).filter((e) => statSync(join(dir, e)).isDirectory())
    const groups = dirs.filter((e) => e.startsWith('(') && e.endsWith(')'))
    if (rest.length > 0) {
      const [head, ...tail] = rest
      if (dirs.includes(head)) {
        const hit = walk(join(dir, head), tail)
        if (hit) return hit
      }
      for (const g of groups) {
        const hit = walk(join(dir, g), rest)
        if (hit) return hit
      }
      for (const d of dirs.filter((e) => /^\[[^.\]]+\]$/.test(e))) {
        const hit = walk(join(dir, d), tail)
        if (hit) return hit
      }
      return null
    }
    for (const g of groups) {
      const hit = walk(join(dir, g), rest)
      if (hit) return hit
    }
    return null
  }
  const hit = walk(APP, url.split('?')[0].split('/').filter(Boolean))
  return hit ? relative(APP, hit) : null
}

const asset = (type: string) => ({
  id: ID,
  name: `member-${type}`,
  type,
  criticality: 'high',
  riskScore: 42,
  exposure: 'public',
  findingCount: 3,
  status: 'active',
  scope: 'external',
  tags: [],
  metadata: {},
})

const REGISTRY_TYPES = Object.keys(ASSET_TYPE_CLASSES)

describe('asset group member links', () => {
  beforeEach(() => {
    replace.mockClear()
    current = null
  })

  it('open the generic asset detail page', () => {
    expect(groupMemberHref(ID)).toBe(`/assets/${ID}`)
    expect(resolvePage(groupMemberHref(ID))).toBe(
      join('(dashboard)', '(discovery)', 'assets', '[id]', 'page.tsx')
    )
  })

  it('the resolver tells a missing route from a real one', () => {
    // The old per-type targets: no page, the click 404'd.
    expect(resolvePage(`/assets/domains/${ID}`)).toBeNull()
    expect(resolvePage(`/assets/hosts/${ID}`)).toBeNull()
    expect(resolvePage('/assets/groups')).toBe(
      join('(dashboard)', '(discovery)', 'assets', 'groups', 'page.tsx')
    )
  })

  it('the group page builds member links with groupMemberHref only', () => {
    const src = readFileSync(join(ASSETS_DIR, 'groups', '[id]', 'page.tsx'), 'utf8')
    expect(src.match(/groupMemberHref\(/g)?.length).toBe(2)
    // No per-type detail URL (`/assets/<type>/${id}`); links to groups are fine.
    expect(src).not.toMatch(/`\/assets\/(?!groups\/)[a-z-]+\/\$\{/)
  })

  it('covers every registry type', () => {
    expect(REGISTRY_TYPES.length).toBeGreaterThan(30)
  })

  it.each(REGISTRY_TYPES.filter((t) => t !== 'repository'))(
    '/assets/{id} renders a %s member',
    (type) => {
      current = asset(type)
      render(<AssetDetailPage />)
      expect(screen.getByRole('heading', { name: `member-${type}` })).toBeInTheDocument()
      expect(screen.getByText(ID)).toBeInTheDocument()
      expect(replace).not.toHaveBeenCalled()
    }
  )

  it('/assets/{id} opens a repository in its workspace, at the same URL', () => {
    current = asset('repository')
    render(<AssetDetailPage />)
    expect(screen.getByText(`repository workspace ${ID}`)).toBeInTheDocument()
    expect(replace).not.toHaveBeenCalled()
    expect(resolvePage(`/assets/repositories/${ID}`)).toBeNull()
  })
})
