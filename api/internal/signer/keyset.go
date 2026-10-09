package signer

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// KeySetPath serves the current key set on the signer's socket.
const KeySetPath = "/v1/keyset"

// KeySetWarnBefore is how long before a key set's not_after the signer
// warns that it must be renewed.
const KeySetWarnBefore = 7 * 24 * time.Hour

// ErrKeySetOmitsSigner: the key set does not list the signer's own key, so
// sensors that verify it would refuse every job this signer signs.
var ErrKeySetOmitsSigner = errors.New("key set does not list this signer's key")

// keySet is the key set the signer serves: the envelope as the operator
// signed it, and its parsed document.
type keySet struct {
	mu  sync.RWMutex
	raw []byte
	doc *jobsign.KeySet
}

// LoadKeySet installs a key set envelope after checking it: signed by the
// root it names, not expired, listing this signer's key, and not a lower
// version than the one already loaded. On error the loaded key set is kept.
// The signer never holds the root key; the sensors pin the root.
func (s *Service) LoadKeySet(raw []byte) (*jobsign.KeySet, error) {
	raw = bytes.TrimSpace(raw)
	doc, _, err := jobsign.VerifyKeySet(raw, "", s.now())
	if err != nil {
		return nil, err
	}
	if !doc.HasKey(s.keyID) {
		return nil, fmt.Errorf("%w (%s)", ErrKeySetOmitsSigner, s.keyID)
	}
	s.keyset.mu.Lock()
	defer s.keyset.mu.Unlock()
	if cur := s.keyset.doc; cur != nil && (doc.Version < cur.Version ||
		(doc.Version == cur.Version && !bytes.Equal(raw, s.keyset.raw))) {
		return nil, fmt.Errorf("key set version %d does not replace the loaded version %d", doc.Version, cur.Version)
	}
	s.keyset.raw, s.keyset.doc = raw, doc
	return doc, nil
}

// LoadKeySetFile reads and installs a key set (SIGNER_KEYSET_FILE).
func (s *Service) LoadKeySetFile(path string) (*jobsign.KeySet, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > jobsign.MaxKeySetBytes {
		return nil, fmt.Errorf("key set: %s is not a regular file of at most %d bytes", path, jobsign.MaxKeySetBytes)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied key set path
	if err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	return s.LoadKeySet(raw)
}

// KeySet is the loaded key set envelope and document; nil when none.
func (s *Service) KeySet() ([]byte, *jobsign.KeySet) {
	s.keyset.mu.RLock()
	defer s.keyset.mu.RUnlock()
	return s.keyset.raw, s.keyset.doc
}

// CheckKeySetExpiry logs a warning when the loaded key set expires within
// KeySetWarnBefore, and an error once it has expired (sensors then refuse
// every job until a new one is deployed).
func (s *Service) CheckKeySetExpiry() {
	_, doc := s.KeySet()
	if doc == nil {
		return
	}
	left := doc.NotAfter.Sub(s.now())
	switch {
	case left <= 0:
		s.logger.Error("key set expired: sensors refuse signed jobs until a new key set is deployed",
			"keyset_version", doc.Version, "not_after", doc.NotAfter)
	case left <= KeySetWarnBefore:
		s.logger.Warn("key set expires soon: sign and deploy the next version",
			"keyset_version", doc.Version, "not_after", doc.NotAfter)
	}
}

func (s *Service) handleKeySet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, jobsign.Refusal{Error: "method_not_allowed"})
		return
	}
	raw, _ := s.KeySet()
	if raw == nil {
		writeJSON(w, http.StatusNotFound, jobsign.Refusal{Error: "no_keyset"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
