import type { PillTone } from '@/features/shared/components/tone-pill'
import type { AdminOverview, AdminSystem } from '../types'
import { hoursAgo, levelTone } from './system'

/** The console page of the platform's own sensors (research/389). */
export const PLATFORM_SENSORS_URL = '/sensors'

/** One tile of the Overview's installation strip. */
export interface HealthTile {
  key: 'services' | 'storage' | 'backup' | 'sensors' | 'database'
  labelKey: string
  label: string
  tone: PillTone
  /** The state, in words (the pill's text): never colour alone. */
  stateKey: string
  state: string
  /** One short line under the state. */
  detailKey?: string
  detail?: string
  vars?: Record<string, string | number>
  href: string
}

const SERVICE_NAMES: Record<string, string> = {
  api: 'API',
  postgres: 'PostgreSQL',
  redis: 'Redis',
  web: 'Web',
  gateway: 'Gateway',
}

/**
 * "Is the platform healthy?" in five tiles: services, storage, backups,
 * platform sensors and the database schema. Each says its state in words
 * and links to the page that explains it. Built from the two reads the
 * Overview already makes (/overview and /system); nothing new is fetched.
 */
export function buildHealthTiles(o: AdminOverview, sys: AdminSystem): HealthTile[] {
  return [servicesTile(sys), storageTile(sys), backupTile(sys), sensorsTile(o), databaseTile(o)]
}

function servicesTile(sys: AdminSystem): HealthTile {
  // The sensors row has its own tile; it is not a service an operator restarts.
  const checked = sys.services.filter((s) => s.configured && s.name !== 'sensors')
  const down = checked.filter((s) => !s.ok)
  const base = {
    key: 'services',
    labelKey: 'admin.health.services',
    label: 'Services',
    href: '/health',
  } as const
  if (down.length > 0) {
    return {
      ...base,
      tone: 'destructive',
      stateKey: 'admin.health.servicesDown',
      state: '{count, plural, one {# not answering} other {# not answering}}',
      detail: '{names}',
      detailKey: 'admin.health.servicesDownDetail',
      vars: {
        count: down.length,
        names: down.map((s) => SERVICE_NAMES[s.name] ?? s.name).join(', '),
      },
    }
  }
  return {
    ...base,
    tone: 'success',
    stateKey: 'admin.health.servicesUp',
    state: 'All answering',
    detailKey: 'admin.health.servicesUpDetail',
    detail: '{count, plural, one {# service checked} other {# services checked}}',
    vars: { count: checked.length },
  }
}

function storageTile(sys: AdminSystem): HealthTile {
  const base = {
    key: 'storage',
    labelKey: 'admin.health.storage',
    label: 'Storage',
    href: '/health',
  } as const
  const vols = sys.storage.volumes.filter((v) => v.ok)
  if (vols.length === 0) {
    return { ...base, tone: 'muted', stateKey: 'admin.health.notReported', state: 'Not reported' }
  }
  const worst = vols.reduce((a, b) => (b.free_ratio < a.free_ratio ? b : a))
  const level = Math.max(...vols.map((v) => v.level))
  return {
    ...base,
    tone: levelTone(level),
    stateKey: 'admin.health.storageFree',
    state: '{percent}% free',
    detailKey: 'admin.health.storageDetail',
    detail: 'Lowest: {name}',
    vars: { percent: Math.round(worst.free_ratio * 100), name: worst.name },
  }
}

function backupTile(sys: AdminSystem): HealthTile {
  const b = sys.backup
  const base = {
    key: 'backup',
    labelKey: 'admin.health.backups',
    label: 'Backups',
    href: '/health',
  } as const
  if (!b.reported) {
    return {
      ...base,
      tone: 'muted',
      stateKey: 'admin.health.notReported',
      state: 'Not reported',
      detailKey: 'admin.health.backupUnknownDetail',
      detail: 'The console cannot tell',
    }
  }
  const hours = hoursAgo(b.age_seconds)
  const detail =
    hours === null
      ? {}
      : {
          detailKey: 'admin.health.backupAge',
          detail: '{hours, plural, one {Last success # hour ago} other {Last success # hours ago}}',
          vars: { hours },
        }
  if (b.last_failed) {
    return {
      ...base,
      tone: 'destructive',
      stateKey: 'admin.health.backupFailed',
      state: 'Last run failed',
      ...detail,
    }
  }
  return {
    ...base,
    tone: levelTone(b.level),
    stateKey: b.level > 0 ? 'admin.health.backupStale' : 'admin.health.backupOk',
    state: b.level > 0 ? 'Out of date' : 'Up to date',
    ...detail,
  }
}

function sensorsTile(o: AdminOverview): HealthTile {
  const s = o.platform.platform_sensors
  const base = {
    key: 'sensors',
    labelKey: 'admin.health.platformSensors',
    label: 'Platform sensors',
    href: PLATFORM_SENSORS_URL,
  } as const
  if (s.total === 0) {
    return { ...base, tone: 'muted', stateKey: 'admin.health.sensorsNone', state: 'None connected' }
  }
  return {
    ...base,
    tone: s.online === 0 ? 'destructive' : s.offline > 0 ? 'warning' : 'success',
    stateKey: 'admin.health.sensorsOnline',
    state: '{online} of {total} online',
    vars: { online: s.online, total: s.total },
  }
}

function databaseTile(o: AdminOverview): HealthTile {
  const p = o.platform
  const base = {
    key: 'database',
    labelKey: 'admin.health.database',
    label: 'Database schema',
    href: '/health',
    detailKey: 'admin.health.schemaVersion',
    detail: 'Version {version}',
    vars: { version: p.schema_version },
  } as const
  if (!p.schema_known) {
    return { ...base, tone: 'muted', stateKey: 'admin.health.notReported', state: 'Not reported' }
  }
  if (p.schema_dirty) {
    return {
      ...base,
      tone: 'destructive',
      stateKey: 'admin.health.schemaDirty',
      state: 'Migration stopped midway',
    }
  }
  if (p.schema_shipped > 0 && p.schema_version < p.schema_shipped) {
    return {
      ...base,
      tone: 'destructive',
      stateKey: 'admin.health.schemaBehind',
      state: 'Behind this release',
    }
  }
  if (p.schema_shipped > 0 && p.schema_version > p.schema_shipped) {
    return {
      ...base,
      tone: 'warning',
      stateKey: 'admin.health.schemaAhead',
      state: 'Newer than this release',
    }
  }
  return { ...base, tone: 'success', stateKey: 'admin.health.schemaOk', state: 'In sync' }
}
