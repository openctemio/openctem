package vulnbundle

// The advisory cards travel as the "cards" stream of the signed intel side
// manifest (intel.go): one card per line, ids ascending, only reported, reviewed or
// withdrawn cards. A platform that does not know the stream skips it.

import (
	"errors"
	"fmt"

	"github.com/openctemio/openctem/server/pkg/domain/advisory"
)

// Cards stream.
const (
	IntelStreamCards = "cards"
	// MaxIntelCardsBytes caps the compressed cards file.
	MaxIntelCardsBytes = 16 << 20
)

// ParseIntelCards checks the cards file against the verified manifest
// (size, SHA-256, record count, the stream's format version) and decodes
// it: every card validated, ids ascending and unique.
func ParseIntelCards(gz []byte, s *IntelStream) ([]*advisory.Card, error) {
	if s.Version != advisory.Schema {
		return nil, fmt.Errorf("intel cards: format %q is not %s", clipModel(s.Version), advisory.Schema)
	}
	zr, err := openIntelStream(gz, s, MaxIntelCardsBytes, advisory.MaxCards)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out := make([]*advisory.Card, 0, s.File.Records)
	last := ""
	err = scanLines(&limited{r: zr, left: int64(advisory.MaxCards) * advisory.MaxCardBytes}, func(line []byte) error {
		if len(out) >= s.File.Records {
			return errors.New("more cards than the manifest states")
		}
		c, err := advisory.Decode(line)
		if err != nil {
			return err
		}
		if c.ID <= last {
			return fmt.Errorf("card %s is repeated or out of order", c.ID)
		}
		last = c.ID
		out = append(out, c)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("intel cards: %w", err)
	}
	if len(out) != s.File.Records {
		return nil, fmt.Errorf("intel cards: %d cards, the manifest states %d", len(out), s.File.Records)
	}
	return out, nil
}
