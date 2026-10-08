### Fixed: SBOM export is a valid CycloneDX 1.6 or SPDX 2.3 document built by the server

- New `GET /api/v1/components/sbom?format=cyclonedx|spdx[&asset_id=]`
  (`components:read`) returns CycloneDX 1.6 JSON (default) or SPDX 2.3 JSON
  of the components the organization's assets use, or of one asset, with
  the licenses the organization's assets report (SPDX ids where they are
  one) and the vulnerability count per component. A restricted member gets
  only components of assets in their data scope; an asset outside it is not
  found. Above 10000 components the export is refused (export one asset at
  a time) instead of being cut short.
- The Components > Export SBOM page downloads that document. It used to
  build a file in the browser after a simulated 1.5 s wait that was not
  valid CycloneDX or SPDX (and offered XML and options it did not apply).
- Removed: `GET /api/v1/components/export` (the browser-side builder's
  source).
