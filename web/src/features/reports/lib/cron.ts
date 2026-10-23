/**
 * Lightweight cron humanizer for the 5-field standard cron the backend parses
 * (minute hour dom month dow, see reportschedule.cronParser). There is no
 * existing cron helper in the codebase, and pulling in `cronstrue` would add a
 * dependency for one label, so this covers the common cadences the presets
 * produce and falls back to the raw expression for anything custom.
 */

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/** The weekday's long name in the app locale (0 = Sunday), from Intl. */
export function weekdayName(dow: number, locale?: string): string {
  // 2024-01-07 is a Sunday.
  return new Date(Date.UTC(2024, 0, 7 + (dow % 7))).toLocaleDateString(locale, {
    weekday: 'long',
    timeZone: 'UTC',
  })
}

function pad(n: string): string {
  return n.padStart(2, '0')
}

/** Format `hour minute` cron fields as HH:MM, or null if not a fixed time. */
function fixedTime(minute: string, hour: string): string | null {
  if (!/^\d+$/.test(minute) || !/^\d+$/.test(hour)) return null
  return `${pad(hour)}:${pad(minute)}`
}

/** A cron expression in words, in the app language; custom ones stay as written. */
export function humanizeCron(expr: string, t: Translate, locale?: string): string {
  const parts = expr.trim().split(/\s+/)
  if (parts.length !== 5) return expr
  const [minute, hour, dom, month, dow] = parts

  const time = fixedTime(minute, hour)

  // Daily: fixed time, every day/month/dow
  if (time && dom === '*' && month === '*' && dow === '*') {
    return t('reports.cron.daily', 'Daily at {time}', { time })
  }
  // Weekly: fixed time on a single weekday
  if (time && dom === '*' && month === '*' && /^\d+$/.test(dow)) {
    return t('reports.cron.weekly', 'Weekly on {day} at {time}', {
      day: weekdayName(Number(dow), locale),
      time,
    })
  }
  // Monthly: fixed time on a single day-of-month
  if (time && /^\d+$/.test(dom) && month === '*' && dow === '*') {
    return t('reports.cron.monthly', 'Monthly on day {day} at {time}', { day: dom, time })
  }
  // Hourly: every hour at a fixed minute
  if (/^\d+$/.test(minute) && hour === '*' && dom === '*' && month === '*' && dow === '*') {
    return t('reports.cron.hourly', 'Hourly at :{minute}', { minute: pad(minute) })
  }

  return expr
}

export interface CronPreset {
  /** i18n key of the preset's name (the fallback is the English text). */
  labelKey: string
  fallback: string
  /** Builds the cron expression for the chosen local time (HH:MM). */
  build: (hour: number, minute: number, weekday: number, monthDay: number) => string
}

export const CRON_PRESETS: Record<string, CronPreset> = {
  daily: {
    labelKey: 'reports.cron.preset.daily',
    fallback: 'Daily',
    build: (h, m) => `${m} ${h} * * *`,
  },
  weekly: {
    labelKey: 'reports.cron.preset.weekly',
    fallback: 'Weekly',
    build: (h, m, weekday) => `${m} ${h} * * ${weekday}`,
  },
  monthly: {
    labelKey: 'reports.cron.preset.monthly',
    fallback: 'Monthly',
    build: (h, m, _weekday, monthDay) => `${m} ${h} ${monthDay} * *`,
  },
  custom: {
    labelKey: 'reports.cron.preset.custom',
    fallback: 'Custom cron',
    build: () => '',
  },
}
