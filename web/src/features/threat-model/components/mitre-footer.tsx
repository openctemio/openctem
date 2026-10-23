'use client'

import { useTranslation } from '@/context/i18n-provider'

/**
 * Required MITRE ATT&CK attribution notice. Rendered wherever ATT&CK
 * technique / tactic / mitigation ids are displayed.
 */
export function MitreFooter() {
  const { t } = useTranslation()
  return (
    <p className="text-muted-foreground mt-6 text-xs">
      {t(
        'threatModel.mitreNotice',
        '© The MITRE Corporation. ATT&CK® is a registered trademark of The MITRE Corporation. ATT&CK technique, tactic, and mitigation identifiers are reproduced with permission.'
      )}
    </p>
  )
}
