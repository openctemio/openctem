package ctisformats

import (
	"testing"

	"github.com/openctemio/ctis/v2/importer"
)

// Every standard format the platform accepts on upload is registered.
func TestStandardFormatsRegistered(t *testing.T) {
	for _, f := range []importer.Format{importer.FormatSARIF, importer.FormatCycloneDX, importer.FormatSPDX,
		importer.FormatCSAF, importer.FormatOpenVEX} {
		if !importer.Registered(f) {
			t.Errorf("format %s is not registered", f)
		}
	}
}
