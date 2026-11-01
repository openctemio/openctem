package sensorpairing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
)

// The approver picks the fingerprint the host shows out of three
// (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md §4.5). A tick box
// can be clicked without looking; a pick needs the host's screen, which is
// also the proof typing the code used to give before the code arrived in a
// link. The two decoys come from a key only the platform holds and the
// pairing id: stable across reloads, different for every request, and in an
// order no client can predict.

const (
	choiceCount    = 3
	decoyAttempts  = 32
	decoyDomain    = "openctem/sensor-pairing/decoy/v1\x00"
	choiceOrderTag = "openctem/sensor-pairing/choice-order/v1\x00"
)

// decoyKey keys the decoys and their order; it derives from the platform
// pairing key, so it never leaves the platform.
func (s *Service) decoyKey() []byte {
	m := hmac.New(sha256.New, s.platformKey.Seed())
	m.Write([]byte("openctem/sensor-pairing/decoy-key/v1"))
	return m.Sum(nil)
}

// fingerprintChoices returns the request's SAS and two decoys that differ
// from it, and from each other, in the number and in every word, ordered by
// a keyed hash. Nil when the request has no SAS yet.
func (s *Service) fingerprintChoices(p *sensordom.Pairing) []string {
	sas, ok := parseSAS(p.SAS)
	if !ok {
		return nil
	}
	key := s.decoyKey()
	picked := []pairing.SAS{sas}
	for i := 0; i < decoyAttempts && len(picked) < choiceCount; i++ {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(decoyDomain))
		m.Write([]byte(p.ID.String()))
		m.Write([]byte{byte(i)})
		d := m.Sum(nil)
		c := pairing.SAS{Number: fmt.Sprintf("%03d", (int(d[0])<<8|int(d[1]))%1000),
			Words: [3]string{pairing.Words[d[2]], pairing.Words[d[3]], pairing.Words[d[4]]}}
		if distinctFromAll(c, picked) {
			picked = append(picked, c)
		}
	}
	out := make([]string, len(picked))
	for i, c := range picked {
		out[i] = c.String()
	}
	order := func(v string) string {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(choiceOrderTag))
		m.Write([]byte(p.ID.String()))
		m.Write([]byte(v))
		return string(m.Sum(nil))
	}
	sort.Slice(out, func(i, j int) bool { return order(out[i]) < order(out[j]) })
	return out
}

func distinctFromAll(c pairing.SAS, others []pairing.SAS) bool {
	for _, o := range others {
		if c.Number == o.Number {
			return false
		}
		for i := range c.Words {
			if c.Words[i] == o.Words[i] {
				return false
			}
		}
	}
	return true
}

// parseSAS reads the stored form "512 · tiger · violet · anchor".
func parseSAS(v string) (pairing.SAS, bool) {
	parts := strings.Split(v, "·")
	if len(parts) != 4 {
		return pairing.SAS{}, false
	}
	var out pairing.SAS
	out.Number = strings.TrimSpace(parts[0])
	for i := range out.Words {
		out.Words[i] = strings.TrimSpace(parts[i+1])
	}
	return out, out.Number != ""
}

// canonicalFingerprint drops spacing and case so a pick compares however a
// client rendered it.
func canonicalFingerprint(v string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(v) {
		if r == ' ' || r == '\t' || r == '·' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// sameFingerprint compares the pick with the SAS in constant time.
func sameFingerprint(picked, sas string) bool {
	if sas == "" {
		return false
	}
	return hmac.Equal([]byte(canonicalFingerprint(picked)), []byte(canonicalFingerprint(sas)))
}

// fingerprintMismatch closes the request a wrong pick was made on, audits
// it and tells every administrator: an approver who picks a fingerprint
// the host did not show is either mistaken or being coached by whoever
// started that sensor.
func (s *Service) fingerprintMismatch(ctx context.Context, actor Actor, p *sensordom.Pairing, code string) {
	codeHash := ""
	if norm, err := pairing.NormalizeCode(code); err == nil {
		codeHash = s.codeHash(norm)
	}
	if _, err := s.repo.Deny(ctx, actor.TenantID, p.ID, actor.UserID, codeHash, s.now()); err != nil {
		s.log.Warn("sensor pairing: closing a request after a wrong fingerprint failed", "pairing_id", p.ID.String(), "error", err)
	}
	from := ipString(p)
	msg := fmt.Sprintf("Sensor pairing closed: %s picked a fingerprint the sensor did not show (request from %s). "+
		"If nobody on your team started this sensor, someone may be trying to get it approved.", actor.Email, firstNonEmpty(from, "an unknown address"))
	s.logAudit(ctx, s.auditContext(actor), auditapp.NewFailureEvent(auditdom.ActionSensorPairingDenied, auditdom.ResourceTypeSensor, p.ID.String(), ErrFingerprintMismatch).
		WithMessage(msg).WithSeverity(auditdom.SeverityHigh).
		WithMetadata("reason", "fingerprint_mismatch").
		WithMetadata("key_fingerprint", pairing.KeyFingerprint(p.Thumbprint)).
		WithMetadata("source_ip", from).WithMetadata("host_facts", p.HostFacts))
	s.notifyAdmins(ctx, actor.TenantID, "Sensor pairing closed: wrong fingerprint", msg, "high")
}
