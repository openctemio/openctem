'use client'

import { TENABLE_CONNECTOR_ENABLED } from '@/features/integrations/config/feature-gates'
import { ScannerImportsView } from '@/features/integrations/components/scanners/scanner-imports-view'
import { TenableConnectorView } from '@/features/integrations/components/scanners/tenable-connector-view'

/**
 * Vulnerability scanners: the Tenable.sc connector view (Beta) while
 * TENABLE_CONNECTOR_ENABLED, otherwise only the .nessus import and paused
 * rows; see features/integrations/config/feature-gates.ts.
 */
export default function SecurityScannersPage() {
  return TENABLE_CONNECTOR_ENABLED ? <TenableConnectorView /> : <ScannerImportsView />
}
