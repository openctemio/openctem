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
	xrv "github.com/mattermost/xml-roundtrip-validator"
	"github.com/openctemio/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
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
//   - the document has no DTD, and each namespace prefix in it stands for one
//     namespace;
//   - the root is a samlp:Response holding exactly one plaintext assertion and
//     no encrypted one (the library would pick the first of several);
//   - the assertion itself is signed by the configured IdP certificate, even
//     when the response is also signed (the library checks only one of them);
//   - no SHA-1 signature or digest method anywhere in the document;
//   - the assertion's shape and conditions (checkSAMLAssertionShape and
//     checkSAMLAssertionConditions), with audience the SP entity ID.
func checkSAMLResponseStrict(raw []byte, certs []*x509.Certificate, clock *dsig.Clock, audience string) (samlStrictResponse, error) {
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return samlStrictResponse{}, samlStrictErr("invalid xml: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return samlStrictResponse{}, samlStrictErr("cannot parse xml: %v", err)
	}
	for _, tok := range doc.Child {
		if _, ok := tok.(*etree.Directive); ok {
			return samlStrictResponse{}, samlStrictErr("document type declarations are not accepted")
		}
	}
	root := doc.Root()
	if root == nil || root.Tag != "Response" || root.NamespaceURI() != samlProtocolNS {
		return samlStrictResponse{}, samlStrictErr("root is not a SAML protocol Response")
	}
	if err := checkSAMLNamespacePrefixes(root); err != nil {
		return samlStrictResponse{}, err
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
	if err := checkSAMLAssertionShape(assertion); err != nil {
		return samlStrictResponse{}, err
	}
	if err := checkSAMLAssertionConditions(assertion, audience, clockNow(clock)); err != nil {
		return samlStrictResponse{}, err
	}
	return samlStrictResponse{assertionID: id}, nil
}

func clockNow(clock *dsig.Clock) time.Time {
	if clock != nil {
		return clock.Now()
	}
	return time.Now()
}

// checkSAMLNamespacePrefixes refuses a document that declares one namespace
// prefix for two different namespaces. The SAML elements are then named the
// same way wherever they appear, so every reader of the document (our
// checks, the signature library and the SAML library) binds each element to
// the same namespace. The default namespace may change between elements as
// usual.
func checkSAMLNamespacePrefixes(root *etree.Element) error {
	bound := map[string]string{}
	check := func(el *etree.Element) error {
		for _, a := range el.Attr {
			if a.Space != "xmlns" {
				continue
			}
			if prev, ok := bound[a.Key]; ok && prev != a.Value {
				return samlStrictErr("namespace prefix %q is bound to two namespaces", a.Key)
			}
			bound[a.Key] = a.Value
		}
		return nil
	}
	if err := check(root); err != nil {
		return err
	}
	for _, el := range root.FindElements(".//*") {
		if err := check(el); err != nil {
			return err
		}
	}
	return nil
}

// Subject confirmation method of the Web Browser SSO profile.
const samlBearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

// checkSAMLAssertionConditions refuses a signed assertion whose conditions the
// library reads more loosely than the SAML profile requires:
//   - the assertion was not issued in the future (beyond the allowed clock
//     skew);
//   - every subject confirmation uses the bearer method;
//   - the Conditions hold at least one AudienceRestriction, and each of them
//     names this service provider (restrictions apply together; the library
//     accepts an assertion with none, or with any one that matches).
func checkSAMLAssertionConditions(assertion *etree.Element, audience string, now time.Time) error {
	if v := strings.TrimSpace(assertion.SelectAttrValue("IssueInstant", "")); v != "" {
		var at saml.RelaxedTime
		if err := at.UnmarshalText([]byte(v)); err != nil {
			return samlStrictErr("assertion IssueInstant is not a time")
		}
		if time.Time(at).After(now.Add(saml.MaxClockSkew)) {
			return samlStrictErr("assertion was issued in the future")
		}
	}
	for _, sc := range assertion.FindElements("./Subject/SubjectConfirmation") {
		if sc.SelectAttrValue("Method", "") != samlBearerMethod {
			return samlStrictErr("subject confirmation is not bearer")
		}
	}
	restrictions := 0
	for _, ar := range assertion.FindElements("./Conditions/AudienceRestriction") {
		restrictions++
		named := false
		for _, aud := range ar.ChildElements() {
			if aud.Tag == "Audience" && strings.TrimSpace(samlElementText(aud)) == audience {
				named = true
			}
		}
		if !named {
			return samlStrictErr("an audience restriction does not name this service provider")
		}
	}
	if restrictions == 0 {
		return samlStrictErr("assertion has no audience restriction")
	}
	return nil
}

// samlElementText is the whole character data of el, comments skipped: what
// the library reads for it (its chardata binding concatenates every text
// segment). etree's Text() stops at the first token that is neither text nor
// a comment, so a value split by a processing instruction would be read as
// only its first part.
func samlElementText(el *etree.Element) string {
	var b strings.Builder
	for _, tok := range el.Child {
		if cd, ok := tok.(*etree.CharData); ok {
			b.WriteString(cd.Data)
		}
	}
	return b.String()
}

// Assertion element names the shape check reads.
const (
	samlTagIssuer                  = "Issuer"
	samlTagSubject                 = "Subject"
	samlTagConditions              = "Conditions"
	samlTagNameID                  = "NameID"
	samlTagEncryptedID             = "EncryptedID"
	samlTagBaseID                  = "BaseID"
	samlTagSubjectConfirmation     = "SubjectConfirmation"
	samlTagSubjectConfirmationData = "SubjectConfirmationData"
)

// samlIdentifierTags are the subject identifier elements (one choice of the
// three in the SAML schema).
var samlIdentifierTags = map[string]bool{samlTagNameID: true, samlTagEncryptedID: true, samlTagBaseID: true}

// samlNamespaceBlindTags are the assertion elements the library binds by
// local name in any namespace: the subject identifiers and the elements its
// condition, audience and confirmation checks read.
var samlNamespaceBlindTags = map[string]bool{
	samlTagNameID: true, samlTagEncryptedID: true, samlTagBaseID: true,
	samlTagConditions: true, "AudienceRestriction": true, "Audience": true, "OneTimeUse": true, "ProxyRestriction": true,
	samlTagSubjectConfirmation: true, samlTagSubjectConfirmationData: true,
	"AuthnStatement": true, "AuthnContext": true, "AuthnContextClassRef": true, "SubjectLocality": true,
	"AttributeStatement": true, "Attribute": true, "AttributeValue": true,
}

// checkSAMLAssertionShape refuses a signed assertion the library would read
// wrongly or not survive:
//   - exactly one Issuer, in the assertion namespace, as a direct child, with
//     a value (the library compares it with the IdP entity ID);
//   - exactly one Subject and one Conditions, in the assertion namespace, as
//     direct children (the library dereferences both without a nil check);
//   - no NameID, EncryptedID or BaseID (nor any other element the library
//     binds by local name, such as Conditions or Audience) anywhere in the
//     assertion outside the assertion namespace: the library would read a
//     foreign one as the subject or the conditions;
//   - the Subject rules of checkSAMLSubjectShape.
func checkSAMLAssertionShape(assertion *etree.Element) error {
	counts := map[string]int{}
	var subject *etree.Element
	for _, child := range assertion.ChildElements() {
		switch child.Tag {
		case samlTagIssuer, samlTagSubject, samlTagConditions:
			if child.NamespaceURI() != samlAssertionNS {
				return samlStrictErr("assertion %s is outside the assertion namespace", child.Tag)
			}
			counts[child.Tag]++
			if child.Tag == samlTagIssuer && strings.TrimSpace(child.Text()) == "" {
				return samlStrictErr("assertion Issuer is empty")
			}
			if child.Tag == samlTagSubject {
				subject = child
			}
		}
	}
	for _, tag := range []string{samlTagIssuer, samlTagSubject, samlTagConditions} {
		if counts[tag] != 1 {
			return samlStrictErr("assertion must have exactly one %s, found %d", tag, counts[tag])
		}
	}
	for _, el := range assertion.FindElements(".//*") {
		if samlNamespaceBlindTags[el.Tag] && el.NamespaceURI() != samlAssertionNS {
			return samlStrictErr("%s outside the assertion namespace", el.Tag)
		}
	}
	return checkSAMLSubjectShape(subject)
}

// checkSAMLSubjectShape refuses a Subject with more than one identifier, or
// with no subject confirmation, or with a confirmation that does not carry
// exactly one SubjectConfirmationData: the library dereferences that data
// without a nil check, and checks the request binding and the recipient only
// on the confirmations present.
func checkSAMLSubjectShape(subject *etree.Element) error {
	identifiers, confirmations := 0, 0
	for _, child := range subject.ChildElements() {
		if samlIdentifierTags[child.Tag] {
			identifiers++
		}
		if child.Tag != samlTagSubjectConfirmation {
			continue
		}
		confirmations++
		data := 0
		for _, c := range child.ChildElements() {
			if c.Tag == samlTagSubjectConfirmationData {
				data++
			}
		}
		if data != 1 {
			return samlStrictErr("subject confirmation must have exactly one SubjectConfirmationData, found %d", data)
		}
	}
	if identifiers > 1 {
		return samlStrictErr("subject has %d identifiers", identifiers)
	}
	if confirmations == 0 {
		return samlStrictErr("subject has no SubjectConfirmation")
	}
	return nil
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
	return validateSAMLSignature(vc, detached)
}

// validateSAMLSignature validates el's signature against vc's stored
// certificates. The signature library falls back to the stored certificate
// only when exactly one is configured, so an IdP that signs without an
// embedded certificate would fail every sign-in once a second (rollover)
// certificate is stored. With no embedded certificate and several stored
// ones, each is tried in turn, each with its own validity check. A signature
// that embeds a certificate is validated as before: that certificate must
// exactly match a stored one.
func validateSAMLSignature(vc *dsig.ValidationContext, el *etree.Element) error {
	if el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate") == nil {
		roots, err := vc.CertificateStore.Certificates()
		if err == nil && len(roots) > 1 {
			var first error
			for _, c := range roots {
				one := *vc
				one.CertificateStore = &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{c}}
				_, verr := one.Validate(el)
				if verr == nil {
					return nil
				}
				if first == nil {
					first = verr
				}
			}
			return first
		}
	}
	_, err := vc.Validate(el)
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
	if err := validateSAMLSignature(vc, el); err != nil {
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
