import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { toast } from 'sonner'
import { useAssetCRUD } from '../use-asset-crud'
import type { CreateAssetInput, UpdateAssetInput } from '../../types'

// Mock sonner
vi.mock('sonner', () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
    warning: vi.fn(),
  },
}))

// Mock the asset API functions
const mockCreateAsset = vi.fn()
const mockUpdateAsset = vi.fn()
const mockDeleteAsset = vi.fn()
const mockArchiveAsset = vi.fn()

vi.mock('../use-assets', () => ({
  createAsset: (...args: unknown[]) => mockCreateAsset(...args),
  updateAsset: (...args: unknown[]) => mockUpdateAsset(...args),
  deleteAsset: (...args: unknown[]) => mockDeleteAsset(...args),
  archiveAsset: (...args: unknown[]) => mockArchiveAsset(...args),
}))

// Mock error handler (keeps the real ApiClientError for the 409 refusal)
vi.mock('@/lib/api/error-handler', async () => {
  const actual =
    await vi.importActual<typeof import('@/lib/api/error-handler')>('@/lib/api/error-handler')
  return { ...actual, getErrorMessage: (_err: unknown, fallback: string) => fallback }
})

const { ApiClientError } = await import('@/lib/api/error-handler')
const refused = () =>
  new ApiClientError('has findings', 'CONFLICT', 409, {
    reason: 'asset_has_findings',
    finding_count: 3,
  })

describe('useAssetCRUD', () => {
  const mockMutate = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    mockMutate.mockResolvedValue(undefined)
    mockCreateAsset.mockResolvedValue({ id: 'new-1', name: 'Test' })
    mockUpdateAsset.mockResolvedValue({ id: '1', name: 'Updated' })
    mockDeleteAsset.mockResolvedValue(undefined)
    mockArchiveAsset.mockResolvedValue({ id: '1' })
  })

  // ============================================
  // handleCreate
  // ============================================
  describe('handleCreate', () => {
    it('calls createAsset with data and asset type, then mutate on success', async () => {
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))

      const input: CreateAssetInput = { name: 'example.com', type: 'domain' }
      let returnValue: boolean | undefined

      await act(async () => {
        returnValue = await result.current.handleCreate(input)
      })

      expect(mockCreateAsset).toHaveBeenCalledWith({ ...input, type: 'domain' })
      expect(mockMutate).toHaveBeenCalled()
      expect(returnValue).toBe(true)
    })

    it('shows success toast on successful creation', async () => {
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))

      await act(async () => {
        await result.current.handleCreate({ name: 'test.com', type: 'domain' })
      })

      expect(toast.success).toHaveBeenCalledWith('Domain created successfully')
    })

    it('shows error toast on failure and returns false', async () => {
      mockCreateAsset.mockRejectedValue(new Error('Network error'))
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))

      let returnValue: boolean | undefined

      await act(async () => {
        returnValue = await result.current.handleCreate({ name: 'test.com', type: 'domain' })
      })

      expect(toast.error).toHaveBeenCalledWith('Failed to create domain')
      expect(returnValue).toBe(false)
      expect(mockMutate).not.toHaveBeenCalled()
    })
  })

  // ============================================
  // handleUpdate
  // ============================================
  describe('handleUpdate', () => {
    it('calls updateAsset with correct id and data', async () => {
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))

      const updateData: UpdateAssetInput = { name: 'updated.com' }

      await act(async () => {
        await result.current.handleUpdate('asset-1', updateData)
      })

      expect(mockUpdateAsset).toHaveBeenCalledWith('asset-1', updateData)
      expect(mockMutate).toHaveBeenCalled()
      expect(toast.success).toHaveBeenCalledWith('Domain updated successfully')
    })

    it('shows error toast on update failure', async () => {
      mockUpdateAsset.mockRejectedValue(new Error('Not found'))
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))

      const returnValue = await act(async () => {
        return await result.current.handleUpdate('asset-1', { name: 'x' })
      })

      expect(toast.error).toHaveBeenCalledWith('Failed to update domain')
      expect(returnValue).toBe(false)
    })
  })

  // ============================================
  // handleDelete
  // ============================================
  describe('handleDelete', () => {
    it('calls deleteAsset with correct id and mutates', async () => {
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))

      await act(async () => {
        await result.current.handleDelete('asset-1')
      })

      expect(mockDeleteAsset).toHaveBeenCalledWith('asset-1')
      expect(mockMutate).toHaveBeenCalled()
      expect(toast.success).toHaveBeenCalledWith('Domain deleted')
    })

    it('reports a refusal (asset has findings) and offers Archive', async () => {
      mockDeleteAsset.mockRejectedValue(refused())
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))

      const returnValue = await act(async () => {
        return await result.current.handleDelete('asset-1', 'example.com')
      })

      expect(returnValue).toBe('refused')
      expect(toast.error).not.toHaveBeenCalled()
      const [message, opts] = vi.mocked(toast.warning).mock.calls[0] as [
        string,
        { action: { label: string; onClick: () => void } },
      ]
      expect(message).toContain('example.com was not deleted: it has 3 findings')
      expect(opts.action.label).toBe('Archive')
      await act(async () => {
        opts.action.onClick()
        await Promise.resolve()
      })
      expect(mockArchiveAsset).toHaveBeenCalledWith('asset-1')
    })

    it('shows error toast on delete failure', async () => {
      mockDeleteAsset.mockRejectedValue(new Error('Forbidden'))
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))

      const returnValue = await act(async () => {
        return await result.current.handleDelete('asset-1')
      })

      expect(toast.error).toHaveBeenCalledWith('Failed to delete Domain')
      expect(returnValue).toBe('failed')
    })
  })

  // ============================================
  // handleBulkDelete
  // ============================================
  describe('handleBulkDelete', () => {
    it('deletes each asset and reports deleted, refused and failed', async () => {
      mockDeleteAsset.mockImplementation(async (id: string) => {
        if (id === 'id-2') throw refused()
        if (id === 'id-3') throw new Error('boom')
      })
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))

      let returnValue: boolean | undefined
      await act(async () => {
        returnValue = await result.current.handleBulkDelete(['id-1', 'id-2', 'id-3'])
      })

      expect(mockDeleteAsset).toHaveBeenCalledTimes(3)
      expect(mockMutate).toHaveBeenCalled()
      expect(returnValue).toBe(true)
      expect(toast.success).toHaveBeenCalledWith('Deleted 1 asset')
      expect(vi.mocked(toast.warning).mock.calls[0][0]).toContain(
        '1 asset not deleted because it has findings'
      )
      expect(toast.error).toHaveBeenCalledWith('Failed to delete 1 asset')
    })

    it('enforces MAX_BULK_DELETE=100 limit', async () => {
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))

      const tooManyIds = Array.from({ length: 101 }, (_, i) => `id-${i}`)

      const returnValue = await act(async () => {
        return await result.current.handleBulkDelete(tooManyIds)
      })

      expect(toast.error).toHaveBeenCalledWith('Cannot delete more than 100 items at once')
      expect(mockDeleteAsset).not.toHaveBeenCalled()
      expect(returnValue).toBe(false)
    })

    it('returns false for empty array without calling API', async () => {
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))

      const returnValue = await act(async () => {
        return await result.current.handleBulkDelete([])
      })

      expect(returnValue).toBe(false)
      expect(mockDeleteAsset).not.toHaveBeenCalled()
    })
  })

  // ============================================
  // isSubmitting state
  // ============================================
  describe('isSubmitting state', () => {
    it('starts as false', () => {
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))
      expect(result.current.isSubmitting).toBe(false)
    })

    it('is false after successful operation completes', async () => {
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))

      await act(async () => {
        await result.current.handleCreate({ name: 'test.com', type: 'domain' })
      })

      expect(result.current.isSubmitting).toBe(false)
    })

    it('is false after failed operation completes', async () => {
      mockCreateAsset.mockRejectedValue(new Error('fail'))
      const { result } = renderHook(() => useAssetCRUD('domain', 'Domain', mockMutate))

      await act(async () => {
        await result.current.handleCreate({ name: 'test.com', type: 'domain' })
      })

      expect(result.current.isSubmitting).toBe(false)
    })
  })
})
