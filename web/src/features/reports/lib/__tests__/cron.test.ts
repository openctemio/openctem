import { describe, it, expect } from 'vitest'
import { humanizeCron, weekdayName } from '../cron'
import en from '@/lib/i18n/dictionaries/en/reports.json'
import vi from '@/lib/i18n/dictionaries/vi/reports.json'

function translator(dict: Record<string, string>) {
  return (key: string, fallback?: string, vars?: Record<string, string | number>) =>
    (dict[key] ?? fallback ?? key).replace(/\{(\w+)\}/g, (_, k) => String(vars?.[k] ?? `{${k}}`))
}

describe('humanizeCron', () => {
  it('words a daily, weekly, monthly and hourly cadence through t()', () => {
    const t = translator(en)
    expect(humanizeCron('0 8 * * *', t, 'en')).toBe('Daily at 08:00')
    expect(humanizeCron('30 9 * * 1', t, 'en')).toBe('Weekly on Monday at 09:30')
    expect(humanizeCron('0 7 15 * *', t, 'en')).toBe('Monthly on day 15 at 07:00')
    expect(humanizeCron('5 * * * *', t, 'en')).toBe('Hourly at :05')
  })

  it('speaks Vietnamese from the vi dictionary, weekday from Intl', () => {
    const t = translator(vi)
    expect(humanizeCron('0 8 * * *', t, 'vi')).toBe('Hằng ngày lúc 08:00')
    expect(humanizeCron('0 8 * * 1', t, 'vi')).toContain(weekdayName(1, 'vi'))
    expect(weekdayName(1, 'vi')).not.toBe(weekdayName(1, 'en'))
  })

  it('leaves a custom expression as written', () => {
    expect(humanizeCron('*/5 1-3 * * *', translator(en), 'en')).toBe('*/5 1-3 * * *')
  })
})

describe('weekdayName', () => {
  it('is 0 = Sunday, from Intl', () => {
    expect(weekdayName(0, 'en')).toBe('Sunday')
    expect(weekdayName(6, 'en')).toBe('Saturday')
  })
})
