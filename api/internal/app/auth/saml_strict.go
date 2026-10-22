package auth

// SAML response hardening on top of the library's validation: one signed
// assertion, no SHA-1, and each assertion accepted once. Design:
// docs/architecture/saml-sso.md, "Response hardening".

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	samlProtocolNS  = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	xmlDSigNS       = "http://www.w3.org/2000/09/xmldsig#"
)

// errSAMLStrict is the internal reason a response failed the hardening checks.
// It is logged, never returned to the caller (ErrSAMLResponseInvalid is).
var errSAMLStrict = errors.New("saml response refused")

func samlStrictErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errSAMLStrict, fmt.Sprintf(format, args...))
}

// samlWeakAlgorithms are SHA-1 based signature and digest methods. A response
// that uses any of them anywhere is refused: SHA-1 collisions are practical,
// and every supported IdP signs with SHA-256 or stronger.
var samlWeakAlgorithms = map[string]bool{
	dsig.RSASHA1SignatureMethod:                       true,
	dsig.ECDSASHA1SignatureMethod:                     true,
	"http://www.w3.org/2000/09/xmldsig#dsa-sha1":      true,
	"http://www.w3.org/2000/09/xmldsig#hmac-sha1":     true,
	"http://www.w3.org/2000/09/xmldsig#sha1":          true,
	"http://www.w3.org/2009/xmldsig11#dsa-sha1":       true,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha1": true,
}

// refuseWeakSignatureAlgorithms refuses el when any signature or digest method
// under it is SHA-1 based.
func refuseWeakSignatureAlgorithms(el *etree.Element) error {
	for _, path := range []string{".//SignatureMethod", ".//DigestMethod"} {
		for _, m := range el.FindElements(path) {
			if m.NamespaceURI() != xmlDSigNS {
				continue
			}
			alg := strings.TrimSpace(m.SelectAttrValue("Algorithm", ""))
			if samlWeakAlgorithms[alg] {
				return samlStrictErr("weak algorithm %s", alg)
			}
		}
	}
	return nil
}

// samlStrictResponse is what the hardening pre-check learned about a response.
type samlStrictResponse struct {
	assertionID string
}

// checkSAMLResponseStrict enforces what the library leaves optional, before the
// library validates the response:
//   - the root is a samlp:Response holding exactly one plaintext assertion and
//     no encrypted one (the library would pick the first of several);
//   - the assertion itself is signed by the configured IdP certificate, even
//     when the response is also signed (the library checks only one of them);
//   - no SHA-1 signature or digest method anywhere in the document.
func checkSAMLResponseStrict(raw []byte, certs []*x509.Certificate, clock *dsig.Clock) (samlStrictResponse, error) {
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return samlStrictResponse{}, samlStrictErr("invalid xml: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return samlStrictResponse{}, samlStrictErr("cannot parse xml: %v", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "Response" || root.NamespaceURI() != samlProtocolNS {
		return samlStrictResponse{}, samlStrictErr("root is not a SAML protocol Response")
	}
	if err := refuseWeakSignatureAlgorithms(root); err != nil {
		return samlStrictResponse{}, err
	}

	var assertions []*etree.Element
	for _, child := range root.ChildElements() {
		if child.NamespaceURI() != samlAssertionNS {
			continue
		}
		switch child.Tag {
		case "EncryptedAssertion":
			return samlStrictResponse{}, samlStrictErr("encrypted assertions are not accepted")
		case "Assertion":
			assertions = append(assertions, child)
		}
	}
	if len(assertions) != 1 {
		return samlStrictResponse{}, samlStrictErr("expected exactly one assertion, found %d", len(assertions))
	}
	assertion := assertions[0]
	id := strings.TrimSpace(assertion.SelectAttrValue("ID", ""))
	if id == "" {
		return samlStrictResponse{}, samlStrictErr("assertion has no ID")
	}
	hasSig := false
	for _, child := range assertion.ChildElements() {
		if child.Tag == "Signature" && child.NamespaceURI() == xmlDSigNS {
			hasSig = true
			break
		}
	}
	if !hasSig {
		return samlStrictResponse{}, samlStrictErr("assertion is not signed")
	}
	if err := verifySAMLElementSignature(assertion, certs, clock); err != nil {
		return samlStrictResponse{}, samlStrictErr("assertion signature: %v", err)
	}
	return samlStrictResponse{assertionID: id}, nil
}

// verifySAMLElementSignature validates the enveloped signature of el against
// the trusted certificates, with the namespace context of its ancestors (the
// same preparation the library uses for its own checks).
func verifySAMLElementSignature(el *etree.Element, certs []*x509.Certificate, clock *dsig.Clock) error {
	if len(certs) == 0 {
		return errors.New("no trusted certificate")
	}
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return err
	}
	ctx, err = ctx.SubContext(el)
	if err != nil {
		return err
	}
	detached, err := etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return err
	}
	// A KeyInfo without an X509Certificate (for example a bare RSAKeyValue)
	// cannot name a trusted certificate; drop it so the configured one is used.
	if detached.FindElement("./Signature/KeyInfo/X509Data/X509Certificate") == nil {
		if sigEl := detached.FindElement("./Signature"); sigEl != nil {
			if keyInfo := sigEl.FindElement("KeyInfo"); keyInfo != nil {
				sigEl.RemoveChild(keyInfo)
			}
		}
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	vc.IdAttribute = "ID"
	if clock != nil {
		vc.Clock = clock
	}
	_, err = vc.Validate(detached)
	return err
}

// samlNoWeakAlgorithmsVerifier is the library's signature hook: it refuses a
// SHA-1 signature on any element the library verifies (the response
// signature included), then validates as the library would.
type samlNoWeakAlgorithmsVerifier struct{}

func (samlNoWeakAlgorithmsVerifier) VerifySignature(vc *dsig.ValidationContext, el *etree.Element) error {
	if err := refuseWeakSignatureAlgorithms(el); err != nil {
		return err
	}
	if _, err := vc.Validate(el); err != nil {
		return fmt.Errorf("cannot validate signature on %s: %w", el.Tag, err)
	}
	return nil
}

// SAMLReplayStore records an assertion ID once. SetNX reports true only for
// the first caller; the Redis client satisfies it.
type SAMLReplayStore interface {
	SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
}

// SetReplayStore wires the shared store (Redis) that refuses a second use of
// an assertion across every API replica. Without it the service keeps the IDs
// in process, which protects a single replica only.
func (s *SAMLService) SetReplayStore(store SAMLReplayStore) {
	if store != nil {
		s.replay = store
	}
}

// samlReplayKey is the replay-cache key: per organization (another
// organization's IdP may reuse an ID), with the IdP-chosen ID hashed so its
// length and characters never reach the key space.
func samlReplayKey(tenantID shared.ID, assertionID string) string {
	sum := sha256.Sum256([]byte(assertionID))
	return "saml:aid:" + tenantID.String() + ":" + hex.EncodeToString(sum[:])
}

const (
	samlReplayMinTTL = 5 * time.Minute
	samlReplayMaxTTL = 24 * time.Hour
)

// samlReplayTTL keeps an assertion ID for as long as the assertion could still
// be accepted: the latest of its issue window and its NotOnOrAfter limits,
// plus the allowed clock skew and a margin.
func samlReplayTTL(a *saml.Assertion, now time.Time) time.Duration {
	until := a.IssueInstant.Add(saml.MaxIssueDelay)
	if a.Conditions != nil && a.Conditions.NotOnOrAfter.After(until) {
		until = a.Conditions.NotOnOrAfter
	}
	if a.Subject != nil {
		for _, sc := range a.Subject.SubjectConfirmations {
			if sc.SubjectConfirmationData != nil && sc.SubjectConfirmationData.NotOnOrAfter.After(until) {
				until = sc.SubjectConfirmationData.NotOnOrAfter
			}
		}
	}
	ttl := until.Sub(now) + saml.MaxClockSkew + 2*time.Minute
	if ttl < samlReplayMinTTL {
		return samlReplayMinTTL
	}
	if ttl > samlReplayMaxTTL {
		return samlReplayMaxTTL
	}
	return ttl
}

// consumeAssertion records the assertion as used. It fails closed: a store
// error refuses the sign-in, because accepting without the record would let
// a captured response be replayed.
func (s *SAMLService) consumeAssertion(ctx context.Context, tenantID shared.ID, a *saml.Assertion, now time.Time) error {
	if s.replay == nil {
		return samlStrictErr("no replay store")
	}
	first, err := s.replay.SetNX(ctx, samlReplayKey(tenantID, a.ID), "1", samlReplayTTL(a, now))
	if err != nil {
		return samlStrictErr("replay store unavailable: %v", err)
	}
	if !first {
		return samlStrictErr("assertion already used")
	}
	return nil
}

// memorySAMLReplayStore is the single-replica fallback when no Redis client
// is configured. Expired entries are dropped on each insert.
type memorySAMLReplayStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

func newMemorySAMLReplayStore() *memorySAMLReplayStore {
	return &memorySAMLReplayStore{seen: map[string]time.Time{}, now: time.Now}
}

func (m *memorySAMLReplayStore) SetNX(_ context.Context, key, _ string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, exp := range m.seen {
		if !exp.After(now) {
			delete(m.seen, k)
		}
	}
	if exp, ok := m.seen[key]; ok && exp.After(now) {
		return false, nil
	}
	m.seen[key] = now.Add(ttl)
	return true, nil
}
