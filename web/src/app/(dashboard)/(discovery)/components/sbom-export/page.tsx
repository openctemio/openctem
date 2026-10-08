'use client'

import { useState, useMemo } from 'react'
import { Main } from '@/components/layout'
import { PageHeader } from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import {
  Download,
  FileJson,
  FileText,
  CheckCircle,
  Package,
  Shield,
  Scale,
  Clock,
  AlertTriangle,
} from 'lucide-react'
import { SBOM_FORMAT_LABELS } from '@/features/components'
import type { SbomFormat } from '@/features/components'
import { useComponentStatsApi } from '@/features/components/api/use-components-api'
import { downloadSbom } from '@/features/components/api/download-sbom'
import { getErrorMessage } from '@/lib/api/error-handler'
import { toast } from 'sonner'

export default function SBOMExportPage() {
  const { data: apiStats } = useComponentStatsApi()

  const stats = useMemo(
    () => ({
      totalComponents: apiStats?.total_components ?? 0,
      totalVulnerabilities: apiStats?.total_vulnerabilities ?? 0,
      uniqueLicenses: Object.keys(apiStats?.license_risks ?? {}).length,
      cisaKevCount: apiStats?.cisa_kev_components ?? 0,
    }),
    [apiStats]
  )
  const [exportFormat, setExportFormat] = useState<SbomFormat>('cyclonedx')
  const [isExporting, setIsExporting] = useState(false)

  // The API builds the document; the browser only saves it.
  const handleExport = async () => {
    setIsExporting(true)
    try {
      const filename = await downloadSbom(exportFormat)
      toast.success(`SBOM exported as ${filename}`)
    } catch (err) {
      toast.error(getErrorMessage(err, 'SBOM export failed'))
    } finally {
      setIsExporting(false)
    }
  }

  return (
    <>
      <Main>
        <PageHeader
          title="Export SBOM"
          description="Generate Software Bill of Materials in standard formats"
        />

        {/* Summary Stats */}
        <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Card>
            <CardHeader className="pb-2">
              <CardDescription className="flex items-center gap-2">
                <Package className="h-4 w-4" />
                Components
              </CardDescription>
              <CardTitle className="text-3xl">{stats.totalComponents}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">To be included</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardDescription className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-red-500" />
                Vulnerabilities
              </CardDescription>
              <CardTitle className="text-3xl text-red-500">{stats.totalVulnerabilities}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">Count per component</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardDescription className="flex items-center gap-2">
                <Scale className="h-4 w-4 text-blue-500" />
                Licenses
              </CardDescription>
              <CardTitle className="text-3xl text-blue-500">{stats.uniqueLicenses}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">As reported by your assets</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardDescription className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-green-500" />
                Format
              </CardDescription>
              <CardTitle className="text-xl text-green-500">
                {SBOM_FORMAT_LABELS[exportFormat]}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">Built by the server</p>
            </CardContent>
          </Card>
        </div>

        <div className="mt-6 grid gap-6 lg:grid-cols-3">
          {/* Export Configuration */}
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>Export Configuration</CardTitle>
              <CardDescription>Customize your SBOM export settings</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Format Selection */}
              <div className="space-y-3">
                <Label>SBOM Format</Label>
                <Select
                  value={exportFormat}
                  onValueChange={(v) => setExportFormat(v as SbomFormat)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(SBOM_FORMAT_LABELS).map(([value, label]) => (
                      <SelectItem key={value} value={value}>
                        <div className="flex flex-wrap items-center gap-2">
                          {value === 'cyclonedx' ? (
                            <FileJson className="h-4 w-4 text-blue-500" />
                          ) : (
                            <FileText className="h-4 w-4 text-green-500" />
                          )}
                          {label}
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  {exportFormat === 'cyclonedx'
                    ? 'CycloneDX is widely supported by security tools and CI/CD pipelines'
                    : 'SPDX is an ISO standard format for software bill of materials'}
                </p>
              </div>

              <Separator />

              <div className="space-y-2 text-sm text-muted-foreground">
                <Label className="text-foreground">What the export holds</Label>
                <p>
                  Every component your assets use that you can see, with its version, package URL,
                  the licenses your assets report and the number of known vulnerabilities. The file
                  validates against the official{' '}
                  {exportFormat === 'cyclonedx' ? 'CycloneDX 1.6' : 'SPDX 2.3'} schema.
                </p>
              </div>

              <Separator />

              {/* Export Button */}
              <Button onClick={handleExport} disabled={isExporting} className="w-full" size="lg">
                {isExporting ? (
                  <>
                    <Clock className="me-2 h-4 w-4 animate-spin" />
                    Exporting...
                  </>
                ) : (
                  <>
                    <Download className="me-2 h-4 w-4" />
                    Export SBOM
                  </>
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Format Info */}
          <Card>
            <CardHeader>
              <CardTitle>About SBOM Formats</CardTitle>
              <CardDescription>Industry-standard formats for software transparency</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="p-4 rounded-lg border bg-blue-500/5 border-blue-500/20">
                <div className="flex items-center gap-2 mb-2">
                  <FileJson className="h-5 w-5 text-blue-500" />
                  <h4 className="font-medium">CycloneDX</h4>
                </div>
                <p className="text-sm text-muted-foreground">
                  Designed for security contexts with comprehensive support for vulnerabilities,
                  licensing, and supply chain metadata.
                </p>
                <div className="flex flex-wrap gap-1 mt-2">
                  <Badge variant="secondary" className="text-xs">
                    OWASP
                  </Badge>
                  <Badge variant="secondary" className="text-xs">
                    ECMA
                  </Badge>
                </div>
              </div>

              <div className="p-4 rounded-lg border bg-green-500/5 border-green-500/20">
                <div className="flex items-center gap-2 mb-2">
                  <FileText className="h-5 w-5 text-green-500" />
                  <h4 className="font-medium">SPDX</h4>
                </div>
                <p className="text-sm text-muted-foreground">
                  ISO/IEC 5962:2021 standard format focused on license compliance and software
                  composition analysis.
                </p>
                <div className="flex flex-wrap gap-1 mt-2">
                  <Badge variant="secondary" className="text-xs">
                    ISO Standard
                  </Badge>
                  <Badge variant="secondary" className="text-xs">
                    Linux Foundation
                  </Badge>
                </div>
              </div>

              <div className="p-4 rounded-lg border">
                <h4 className="font-medium flex items-center gap-2 mb-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  Compliance Ready
                </h4>
                <p className="text-sm text-muted-foreground">
                  Both formats meet requirements for Executive Order 14028 and other regulatory
                  frameworks requiring software transparency.
                </p>
              </div>

              {stats.cisaKevCount > 0 && (
                <div className="p-4 rounded-lg border border-red-500/30 bg-red-500/5">
                  <div className="flex items-center gap-2 mb-2">
                    <AlertTriangle className="h-4 w-4 text-red-500" />
                    <h4 className="font-medium text-red-600">CISA KEV Notice</h4>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {stats.cisaKevCount} component(s) contain vulnerabilities from CISA Known
                    Exploited Vulnerabilities catalog.
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </Main>
    </>
  )
}
