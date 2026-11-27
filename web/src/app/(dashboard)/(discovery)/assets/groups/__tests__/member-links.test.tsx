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
// The page waits for the team and needs assets:read before it renders an asset.
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ isLoading: false }) }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
}))
// The asset under test comes from the hook's own module (not a barrel), so the
// stub holds however the page imports it.
vi.mock('@/features/assets/hooks/use-assets', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useAsset: () => ({ asset: current, isLoading: false, error: null }),
  useAssetPage: () => ({ asset: current, isLoading: false, error: null }),
}))
// Every section of the page (identity, attribution, coverage, ...) fetches its
// own data through the API client. Stub that one seam with requests that never
// settle: each section stays in its loading state, the page shell under test
// stays real, and a section added later or an import path that changes does
// not need this test to change.
vi.mock('@/lib/api/client', async (importOriginal) => {
  const pending = () => new Promise<never>(() => {})
  return {
    ...(await importOriginal<Record<string, unknown>>()),
    apiClient: pending,
    get: pending,
    post: pending,
    put: pending,
    patch: pending,
    del: pending,
    fetcher: pending,
    fetcherWithOptions: pending,
  }
})
// The repository workspace fetches its own data; a stub shows it rendered.
vi.mock('@/features/repositories/components/repository-workspace', () => ({
  RepositoryWorkspace: ({ repositoryId }: { repositoryId: string }) => (
    <div>repository workspace {repositoryId}</div>
  ),
}))

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
      // The page no longer prints the raw id (wording pass: no raw ids in the UI);
      // it is reachable through the Copy ID action instead.
      expect(screen.queryByText(ID)).not.toBeInTheDocument()
      expect(replace).not.toHaveBeenCalled()
    }
  )

  it('/assets/{id} opens a repository in its workspace, at the same URL', async () => {
    current = asset('repository')
    render(<AssetDetailPage />)
    // The workspace code loads on demand.
    expect(await screen.findByText(`repository workspace ${ID}`)).toBeInTheDocument()
    expect(replace).not.toHaveBeenCalled()
    expect(resolvePage(`/assets/repositories/${ID}`)).toBeNull()
  })
})
