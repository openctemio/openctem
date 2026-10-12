import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { planGeneralSave, planHasChanges, type GeneralSavePlanInput } from '../general-save-plan'

const base: GeneralSavePlanInput = {
  orgInfo: { name: 'Acme', slug: 'acme' },
  current: { name: 'Acme', slug: 'acme' },
  generalForm: { timezone: 'UTC', language: 'en', industry: '', website: '' },
  savedGeneral: { timezone: 'UTC', language: 'en', industry: '', website: '' },
  branding: {
    primary_color: '#112233',
    logo_dark_url: 'https://x/dark.png',
    logo_data: 'data:old',
  },
  logoDraft: undefined,
}

describe('planGeneralSave', () => {
  it('nothing changed -> nothing to save', () => {
    expect(planHasChanges(planGeneralSave(base))).toBe(false)
  })

  it('a pending logo is saved by the main Save, with the rest of branding echoed', () => {
    const plan = planGeneralSave({ ...base, logoDraft: 'data:new' })
    expect(planHasChanges(plan)).toBe(true)
    expect(plan.branding).toEqual({
      primary_color: '#112233',
      logo_dark_url: 'https://x/dark.png',
      logo_data: 'data:new',
    })
  })

  it('removing the logo is an explicit null, not an omission', () => {
    const plan = planGeneralSave({ ...base, logoDraft: null })
    expect(plan.branding?.logo_data).toBeNull()
  })

  it('profile and general changes are planned independently of the logo', () => {
    const plan = planGeneralSave({
      ...base,
      orgInfo: { name: 'Acme Inc', slug: 'acme' },
      generalForm: { ...base.generalForm, website: 'https://acme.test' },
    })
    expect(plan.orgChanges).toEqual({ name: 'Acme Inc' })
    expect(plan.general?.website).toBe('https://acme.test')
    expect(plan.branding).toBeNull()
  })
})

describe('organization settings page', () => {
  const src = readFileSync(
    join(process.cwd(), 'src/features/organization/components/organization-settings.tsx'),
    'utf8'
  )
  it('has no second logo-only Save that bypasses the header Save', () => {
    expect(src).toMatch(/planGeneralSave\(/)
    expect(src).not.toMatch(/toast\.success\('Logo updated'\)/)
    expect(src).not.toMatch(/toast\.success\('Logo removed'\)/)
  })
})
