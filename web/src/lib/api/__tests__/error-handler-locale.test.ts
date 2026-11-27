import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/lib/logger', () => ({
  devLog: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))
vi.mock('sonner', () => ({ toast: { error: vi.fn(), success: vi.fn() } }))

import { toast } from 'sonner'
import { registerDictionary } from '@/lib/i18n'
import { vi as viDict } from '@/lib/i18n/dictionaries/vi'
import { ApiClientError, handleApiError } from '../error-handler'

// The global error toast runs outside React: its title follows the page's
// language (<html lang>), not English literals ("Not Found").
describe('handleApiError toast titles', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    registerDictionary('vi', viDict)
    document.documentElement.lang = 'vi'
  })
  afterEach(() => {
    document.documentElement.lang = ''
  })

  it.each([
    [404, 'NOT_FOUND', 'Không tìm thấy'],
    [500, 'INTERNAL_ERROR', 'Lỗi máy chủ'],
    [422, 'VALIDATION_ERROR', 'Kiểm tra lại giá trị đã nhập'],
    [418, 'TEAPOT', 'Lỗi'],
  ])('a %s reads in Vietnamese', (status, code, title) => {
    handleApiError(new ApiClientError('x', code, status))
    expect(toast.error).toHaveBeenCalledTimes(1)
    expect(vi.mocked(toast.error).mock.calls[0][0]).toBe(title)
  })
})
