package component

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseEcosystem_Aliases(t *testing.T) {
	cases := map[string]Ecosystem{
		// canonical values pass through
		"npm":   EcosystemNPM,
		"pypi":  EcosystemPyPI,
		"go":    EcosystemGo,
		"cargo": EcosystemCargo,
		// scanner / PURL aliases normalize to canonical
		"pip":       EcosystemPyPI,
		"PIP":       EcosystemPyPI, // case-insensitive
		"  python ": EcosystemPyPI, // trimmed
		"poetry":    EcosystemPyPI,
		"golang":    EcosystemGo,
		"gomod":     EcosystemGo,
		"rust":      EcosystemCargo,
		"crates":    EcosystemCargo,
		"yarn":      EcosystemNPM,
		"pnpm":      EcosystemNPM,
		"java":      EcosystemMaven,
		"gradle":    EcosystemMaven,
		"dotnet":    EcosystemNuGet,
		"ruby":      EcosystemRubyGems,
		"bundler":   EcosystemRubyGems,
		"php":       EcosystemComposer,
		"elixir":    EcosystemHex,
		"swift":     EcosystemSwiftPM,
		"spm":       EcosystemSwiftPM,
		"dart":      EcosystemPub,
		"flutter":   EcosystemPub,
		// unknown falls back to "other"
		"totallyunknown": EcosystemOther,
		"":               EcosystemOther,
	}

	for in, want := range cases {
		got, err := ParseEcosystem(in)
		assert.NoError(t, err, "input %q", in)
		assert.Equal(t, want, got, "ParseEcosystem(%q)", in)
	}
}
