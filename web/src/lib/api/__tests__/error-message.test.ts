import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { getDictionary, translate } from '@/lib/i18n'

vi.mock('sonner', () => ({ toast: { error: vi.fn() } }))
import { toast } from 'sonner'

import { ApiClientError, getErrorMessage } from '../error-handler'
import {
  describeApiError,
  describeCode,
  isSafeMessage,
  shortReference,
  toastError,
  type Translate,
} from '../error-message'

const en = getDictionary('en')
const viDict = getDictionary('vi')
const tEn: Translate = (k, f, v) => translate(en, k, f, v)
const tVi: Translate = (k, f, v) => translate(viDict, k, f, v)

// The API's registered codes, read from its source: a code the API
// registers without console words fails here.
function registeredCodes(): string[] {
  const src = readFileSync(resolve(__dirname, '../../../../../api/pkg/apierror/codes.go'), 'utf8')
  const block = src.slice(src.indexOf('var registry = map[Code]Spec{'))
  const body = block.slice(0, block.indexOf('\n}\n'))
  const names = [...body.matchAll(/^\s*(Code\w+):/gm)].map((m) => m[1])
  const all =
    readFileSync(resolve(__dirname, '../../../../../api/pkg/apierror/apierror.go'), 'utf8') + src
  const values = new Map(
    [...all.matchAll(/^\s*(Code\w+)\s+Code\s*=\s*"([A-Z0-9_]+)"/gm)].map((m) => [m[1], m[2]])
  )
  return names.map((n) => {
    const v = values.get(n)
    if (!v) throw new Error(`no value for ${n}`)
    return v
  })
}

const UUID = '99999999-9999-4999-8999-999999999999'

describe('every registered API code has console words', () => {
  it('in en and vi', () => {
    const codes = registeredCodes()
    expect(codes.length).toBeGreaterThan(30)
    for (const code of codes) {
      expect(typeof en[`errors.${code}`], `en errors.${code}`).toBe('string')
      expect(typeof viDict[`errors.${code}`], `vi errors.${code}`).toBe('string')
      expect(isSafeMessage(en[`errors.${code}`]), `en errors.${code} is safe`).toBe(true)
    }
  })
  it('action labels exist in both languages', () => {
    for (const key of Object.keys(en).filter(
      (k) => k.startsWith('errors.') && k.endsWith('.action')
    )) {
      expect(typeof viDict[key], key).toBe('string')
    }
  })
})

describe('isSafeMessage', () => {
  it('refuses ids, SQL, network, stacks and paths', () => {
    for (const bad of [
      `integration ${UUID} has no credentials`,
      'ERROR: duplicate key value violates unique constraint "x" (SQLSTATE 23505)',
      'dial tcp 10.0.0.1:443: connect: connection refused',
      "Cannot read properties of undefined (reading 'id')",
      'open /var/lib/x: no such file',
      'x'.repeat(301),
      '',
    ]) {
      expect(isSafeMessage(bad), bad).toBe(false)
    }
    expect(isSafeMessage('Scan profile name is already used.')).toBe(true)
    expect(isSafeMessage('10.0.0.0/8 is outside the scope')).toBe(true)
  })
})

describe('describeApiError', () => {
  it('words a specific code from the dictionary, with its action', () => {
    const err = new ApiClientError('whatever', 'INTEGRATION_NO_CREDENTIALS', 422)
    expect(describeApiError(err, tEn)).toEqual({
      code: 'INTEGRATION_NO_CREDENTIALS',
      message: 'This connection has no API token. Add one to use it.',
      actionLabel: 'Add API token',
    })
    expect(describeApiError(err, tVi).message).toBe(viDict['errors.INTEGRATION_NO_CREDENTIALS'])
  })

  it('keeps a safe server sentence for a generic code, drops an unsafe one', () => {
    expect(
      describeApiError(new ApiClientError('Scan not found', 'NOT_FOUND', 404), tEn).message
    ).toBe('Scan not found')
    const leaky = new ApiClientError(
      `finding ${UUID} is closed`,
      'BAD_REQUEST',
      400,
      undefined,
      'req-1234567890'
    )
    const d = describeApiError(leaky, tEn, 'Could not close the finding.')
    expect(d.message).toBe(en['errors.BAD_REQUEST'])
    expect(JSON.stringify(d)).not.toContain(UUID)
  })

  it('an unexpected failure shows the caller sentence and a short reference', () => {
    const err = new ApiClientError(
      'pq: relation "x" does not exist',
      'INTERNAL_ERROR',
      500,
      undefined,
      'abcdef1234567890'
    )
    const d = describeApiError(err, tEn, 'Could not save the scan.')
    expect(d.message).toBe('Could not save the scan.')
    expect(d.reference).toBe('abcdef12')
    expect(getErrorMessage(err, 'Could not save the scan.')).toBe(
      'Could not save the scan. Reference: abcdef12'
    )
  })

  it('a network failure says so', () => {
    const err = new ApiClientError(
      'Network error - please check your connection',
      'NETWORK_ERROR',
      0
    )
    expect(describeApiError(err, tEn).message).toBe(en['errors.network'])
  })

  it('never shows the text of a runtime error', () => {
    expect(describeApiError(new TypeError('Failed to fetch'), tEn, 'Could not load.').message).toBe(
      'Could not load.'
    )
    expect(
      describeApiError(
        new ApiClientError('Cannot read properties of undefined', 'UNKNOWN_ERROR', 500),
        tEn,
        'Could not load.'
      ).message
    ).toBe('Could not load.')
    // A caller's own sentence in a plain Error is kept.
    expect(describeApiError(new Error('Pick a sensor first.'), tEn).message).toBe(
      'Pick a sensor first.'
    )
  })

  it('interpolates safe params only', () => {
    expect(describeCode('NOT_A_KNOWN_CODE', tEn)).toBeUndefined()
    expect(describeCode('lowercase', tEn)).toBeUndefined()
    const err = new ApiClientError('x', 'INTEGRATION_AUTH_FAILED', 424, { params: { name: UUID } })
    expect(JSON.stringify(describeApiError(err, tEn))).not.toContain(UUID)
  })

  it('validation reasons skip unsafe parts', () => {
    const err = new ApiClientError('Validation failed', 'VALIDATION_FAILED', 422, [
      { field: 'name', message: 'is required' },
      { field: 'owner_id', message: `user ${UUID} not found` },
    ] as unknown as Record<string, unknown>)
    expect(describeApiError(err, tEn).message).toBe('name is required')
  })
})

describe('toastError', () => {
  beforeEach(() => vi.mocked(toast.error).mockClear())
  it('toasts the sentence once per failure, the reference as description', () => {
    const err = new ApiClientError('boom', 'INTERNAL_ERROR', 500, undefined, 'abcdef1234')
    toastError(err, 'Could not test the connection.', tEn)
    expect(toast.error).toHaveBeenCalledWith('Could not test the connection.', {
      id: 'api-error:INTERNAL_ERROR:Could not test the connection.',
      description: 'Reference: abcdef12',
    })
  })
  it('shortReference keeps only id characters', () => {
    expect(shortReference('<script>abc')).toBe('scriptab')
    expect(shortReference(undefined)).toBeUndefined()
  })
})
