/**
 * Tab order per finding source / type. Imported once by the detail page.
 * The type-specific facts (package, credential, resource, …) are sections of
 * the Overview tab (components/detail/finding-type-details.tsx), not panels.
 */

import { registerTypeLayout, registerSourceLayout } from './source-layout'

registerTypeLayout('secret', { hiddenTabs: ['attack-path'] })
registerTypeLayout('misconfiguration', { hiddenTabs: ['attack-path'] })
registerTypeLayout('compliance', { hiddenTabs: ['attack-path'] })

registerSourceLayout('dast', { hiddenTabs: ['attack-path'] })
registerSourceLayout('sca', { hiddenTabs: ['attack-path'] })

for (const source of ['pentest', 'bug_bounty', 'red_team'] as const) {
  registerSourceLayout(source, {
    tabOrder: ['overview', 'pentest', 'evidence', 'remediation', 'related'],
  })
}
