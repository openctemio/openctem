// Package ctisformats registers the CTIS 2.0 standard-format adapters with
// the CTIS importer (docs/architecture/ctis-receiver.md). The core module
// reads only CTIS and the tool-specific formats; SARIF, CycloneDX, SPDX,
// CSAF and OpenVEX are adapter modules that register themselves with
// importer.Register when imported. This is the one place the platform
// imports them: a package that calls importer.Parse on uploads imports this
// package for its side effect.
package ctisformats

import (
	_ "github.com/openctemio/ctis/v2/interop/csaf"      // importer: CSAF
	_ "github.com/openctemio/ctis/v2/interop/cyclonedx" // importer: CycloneDX
	_ "github.com/openctemio/ctis/v2/interop/openvex"   // importer: OpenVEX
	_ "github.com/openctemio/ctis/v2/interop/sarif"     // importer: SARIF
	_ "github.com/openctemio/ctis/v2/interop/spdx"      // importer: SPDX
)
