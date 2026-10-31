'use client'

/**
 * The platform's private certificate authority, as the install commands use
 * it (api docs/how-to/sensors-behind-a-private-ca.md): its certificates with
 * their SHA-256, the pin every command carries (SENSOR_CA_SHA256) and the
 * public download the sensor fetches. One component for the Add sensor
 * dialog and a sensor's own install snippets.
 */

import { useId } from 'react'
import { Download, ShieldCheck } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'

/** One certificate of the platform's CA bundle (API sensorapp.PlatformCACert). */
export interface PlatformCACert {
  common_name: string
  /** Colon-separated upper-case hex. */
  sha256: string
  /** 64 lower-case hex digits: the form SENSOR_CA_SHA256 takes. */
  sha256_hex: string
  root: boolean
  not_after: string
}

/** The platform's private CA (install-templates and config-templates `platform_ca`). */
export interface PlatformCAInfo {
  certificates: PlatformCACert[]
  /** SENSOR_CA_SHA256: the unexpired roots, comma separated. */
  pin: string
  /** The public endpoint that serves the PEM bundle. */
  download_path: string
}

/**
 * The public CA bundle, through the console's own /api/v1 proxy. A constant,
 * never the answer's download_path: a link target does not come from data.
 */
export const PLATFORM_CA_DOWNLOAD_PATH = '/api/v1/sensors/platform-ca'

export function PlatformCAPanel({ ca }: { ca: PlatformCAInfo }) {
  const { t, locale } = useTranslation()
  const titleId = useId()
  const date = (iso: string) => {
    const d = new Date(iso)
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString(locale)
  }
  return (
    <section
      aria-labelledby={titleId}
      className="space-y-2 rounded-lg border p-3 text-xs"
      data-testid="platform-ca"
    >
      <div className="flex items-start gap-2">
        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        <div className="min-w-0 space-y-1">
          <h4 id={titleId} className="text-sm font-medium">
            {t('sensors.platformCa.title')}
          </h4>
          <p className="text-muted-foreground">{t('sensors.platformCa.pinExplain')}</p>
        </div>
      </div>
      <ul className="space-y-2">
        {ca.certificates.map((c) => (
          <li key={c.sha256_hex} className="min-w-0 space-y-0.5" data-testid="platform-ca-cert">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium break-all">{c.common_name}</span>
              <Badge variant={c.root ? 'secondary' : 'outline'} className="text-[11px]">
                {c.root ? t('sensors.platformCa.root') : t('sensors.platformCa.intermediate')}
              </Badge>
              {ca.pin.split(',').includes(c.sha256_hex) && (
                <Badge variant="outline" className="text-[11px]">
                  {t('sensors.platformCa.pinned')}
                </Badge>
              )}
            </div>
            <p className="text-muted-foreground">
              {t('sensors.platformCa.sha256')}{' '}
              <code className="font-mono break-all text-foreground">{c.sha256}</code>
            </p>
            <p className="text-muted-foreground">
              {t('sensors.platformCa.expires', undefined, { date: date(c.not_after) })}
            </p>
          </li>
        ))}
      </ul>
      <Button asChild variant="outline" size="sm" className="h-7 text-xs">
        <a href={PLATFORM_CA_DOWNLOAD_PATH} download="openctem-platform-ca.pem">
          <Download className="h-3.5 w-3.5" aria-hidden />
          {t('sensors.platformCa.download')}
        </a>
      </Button>
    </section>
  )
}
