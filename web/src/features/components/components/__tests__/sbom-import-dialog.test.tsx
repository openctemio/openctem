import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { SbomImportResult } from '../../api/types'

const importSbom = vi.fn()
vi.mock('../../api/hooks', () => ({ importSbom: (...a: unknown[]) => importSbom(...a) }))
vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAssets: () => ({
    assets: [{ id: 'a1', name: 'shop-repo', type: 'repository' }],
    isLoading: false,
  }),
}))

import { MAX_SBOM_BYTES, readSbomFile, SbomImportDialog } from '../sbom-import-dialog'

const preview: SbomImportResult = {
  dry_run: true,
  format: 'cyclonedx',
  spec_version: '1.6',
  components_total: 4,
  components_imported: 3,
  components_skipped: 1,
  direct: 1,
  transitive: 2,
  edges: 2,
  licenses_found: 2,
  ecosystems: [{ value: 'npm', count: 3 }],
  issues: [{ ref: 'bad', name: 'bad', reason: 'invalid package URL' }],
  diff: { added: 2, removed: 1, unchanged: 1 },
}

function sbomFile(body: string) {
  return new File([body], 'bom.json', { type: 'application/json' })
}

beforeEach(() => importSbom.mockReset())

describe('SBOM import wizard', () => {
  it('previews first, then imports what the preview showed', async () => {
    importSbom.mockResolvedValueOnce(preview).mockResolvedValueOnce({
      ...preview,
      dry_run: false,
      written: {
        products_created: 1,
        versions_created: 3,
        links_written: 3,
        edges_written: 2,
        links_removed: 1,
      },
    })
    const onImported = vi.fn()
    render(<SbomImportDialog open onOpenChange={() => {}} onImported={onImported} />)

    await userEvent.click(screen.getByRole('option', { name: /shop-repo/ }))
    await userEvent.upload(
      screen.getByLabelText('SBOM file'),
      sbomFile('{"bomFormat":"CycloneDX"}')
    )
    await userEvent.click(screen.getByRole('button', { name: 'Preview' }))

    await waitFor(() =>
      expect(importSbom).toHaveBeenCalledWith('a1', { bomFormat: 'CycloneDX' }, true)
    )
    expect(await screen.findByText(/2 new, 1 unchanged, 1 recorded/)).toBeTruthy()
    expect(screen.getByText('invalid package URL')).toBeTruthy()

    await userEvent.click(screen.getByRole('button', { name: 'Import 3 packages' }))
    await waitFor(() =>
      expect(importSbom).toHaveBeenLastCalledWith('a1', { bomFormat: 'CycloneDX' }, false)
    )
    expect(onImported).toHaveBeenCalled()
    expect(screen.getByRole('link', { name: /this asset/ }).getAttribute('href')).toBe(
      '/components?asset_id=a1'
    )
  })

  it('refuses a file that is not JSON before calling the API', async () => {
    render(<SbomImportDialog open onOpenChange={() => {}} />)
    await userEvent.click(screen.getByRole('option', { name: /shop-repo/ }))
    await userEvent.upload(screen.getByLabelText('SBOM file'), sbomFile('<bom/>'))
    await userEvent.click(screen.getByRole('button', { name: 'Preview' }))
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(importSbom).not.toHaveBeenCalled()
  })

  it('refuses a file over the size limit without reading it', async () => {
    const text = vi.fn()
    const big = { size: MAX_SBOM_BYTES + 1, text } as unknown as File
    await expect(readSbomFile(big)).rejects.toThrow('too_large')
    expect(text).not.toHaveBeenCalled()
  })
})
