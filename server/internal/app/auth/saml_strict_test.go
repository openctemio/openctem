package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// editResponse decodes a base64 SAMLResponse, lets edit change the document
// and encodes it again.
func editResponse(t *testing.T, b64 string, edit func(root *etree.Element)) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	edit(doc.Root())
	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(out)
}

func childByTag(el *etree.Element, tag string) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == tag {
			return c
		}
	}
	return nil
}

func mustPass(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrSSOFederatedTakeover) {
		t.Fatalf("a valid response must pass validation (stopping at the takeover guard), got %v", err)
	}
}

func mustRefuse(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrSAMLResponseInvalid) {
		t.Fatalf("expected the response to be refused as invalid, got %v", err)
	}
}

// T9: a captured response posted a second time (inside its validity window and
// with the same request binding) is refused.
func TestSAMLAssertionReplayRefused(t *testing.T) {
	f := newSAMLACSFixture(t)
	_, resp := f.respond(t, false, time.Now(), nil)
	mustPass(t, f.post(resp))
	mustRefuse(t, f.post(resp))
}

// The replay cache is per organization and keyed by assertion ID: two
// distinct responses both pass.
func TestSAMLDistinctAssertionsBothAccepted(t *testing.T) {
	f := newSAMLACSFixture(t)
	_, first := f.respond(t, false, time.Now(), nil)
	mustPass(t, f.post(first))
	_, second := f.respond(t, false, time.Now(), nil)
	mustPass(t, f.post(second))
}

type failingReplayStore struct{}

func (failingReplayStore) SetNX(context.Context, string, string, time.Duration) (bool, error) {
	return false, errors.New("redis: connection refused")
}

// T9: without a working replay store the sign-in fails closed.
func TestSAMLReplayCacheDownRefuses(t *testing.T) {
	f := newSAMLACSFixture(t)
	f.svc.SetReplayStore(failingReplayStore{})
	_, resp := f.respond(t, false, time.Now(), nil)
	mustRefuse(t, f.post(resp))
}

// T12: a SHA-1 signed response and assertion is refused.
func TestSAMLSHA1Refused(t *testing.T) {
	f := newSAMLACSFixture(t)
	f.idp.SignatureMethod = dsig.RSASHA1SignatureMethod
	_, resp := f.respond(t, false, time.Now(), nil)
	mustRefuse(t, f.post(resp))
}

// D7(b): a signed response carrying an unsigned assertion is refused; the
// assertion itself must be signed.
func TestSAMLUnsignedAssertionInSignedResponseRefused(t *testing.T) {
	f := newSAMLACSFixture(t)
	_, resp := f.respond(t, false, time.Now(), func(a *saml.IdpAuthnRequest) {
		a.AssertionEl = a.Assertion.Element() // unsigned; MakeResponse signs only the response
	})
	mustRefuse(t, f.post(resp))
}

// D7(b): exactly one assertion. An unsigned response with two signed
// assertions was accepted (the first one won).
func TestSAMLMultipleAssertionsRefused(t *testing.T) {
	f := newSAMLACSFixture(t)
	_, resp := f.respond(t, false, time.Now(), nil)
	resp = editResponse(t, resp, func(root *etree.Element) {
		root.RemoveChild(childByTag(root, "Signature"))
		root.AddChild(childByTag(root, "Assertion").Copy())
	})
	mustRefuse(t, f.post(resp))
}

// An unsigned response with one signed assertion stays valid (IdPs that sign
// only the assertion).
func TestSAMLAssertionOnlySignedAccepted(t *testing.T) {
	f := newSAMLACSFixture(t)
	_, resp := f.respond(t, false, time.Now(), nil)
	resp = editResponse(t, resp, func(root *etree.Element) {
		root.RemoveChild(childByTag(root, "Signature"))
	})
	mustPass(t, f.post(resp))
}

// T10: signature-wrapping variants. Each moves the signed assertion out of
// the place that is read, or forges an assertion next to it.
func TestSAMLXSWCorpus(t *testing.T) {
	forge := func(orig *etree.Element) *etree.Element {
		fake := orig.Copy()
		fake.CreateAttr("ID", "id-forged")
		if sig := childByTag(fake, "Signature"); sig != nil {
			fake.RemoveChild(sig)
		}
		if subj := childByTag(fake, "Subject"); subj != nil {
			if nid := childByTag(subj, "NameID"); nid != nil {
				nid.SetText("attacker@acme.com")
			}
		}
		return fake
	}
	cases := map[string]func(root *etree.Element){
		"forged unsigned assertion before the signed one": func(root *etree.Element) {
			orig := childByTag(root, "Assertion")
			root.InsertChildAt(orig.Index(), forge(orig))
		},
		"signed assertion hidden in Extensions, forged one read": func(root *etree.Element) {
			orig := childByTag(root, "Assertion")
			root.RemoveChild(orig)
			ext := root.CreateElement("samlp:Extensions")
			ext.AddChild(orig)
			root.AddChild(forge(orig))
		},
		"forged assertion carries the original signature": func(root *etree.Element) {
			orig := childByTag(root, "Assertion")
			fake := forge(orig)
			fake.InsertChildAt(1, childByTag(orig, "Signature").Copy())
			root.RemoveChild(orig)
			root.AddChild(fake)
		},
		"signed assertion nested inside the forged one": func(root *etree.Element) {
			orig := childByTag(root, "Assertion")
			fake := forge(orig)
			root.RemoveChild(orig)
			fake.AddChild(orig)
			root.AddChild(fake)
		},
		"response signature removed and assertion signature stripped": func(root *etree.Element) {
			root.RemoveChild(childByTag(root, "Signature"))
			a := childByTag(root, "Assertion")
			a.RemoveChild(childByTag(a, "Signature"))
		},
		"encrypted assertion element": func(root *etree.Element) {
			root.CreateElement("saml:EncryptedAssertion")
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSAMLACSFixture(t)
			_, resp := f.respond(t, false, time.Now(), nil)
			mustRefuse(t, f.post(editResponse(t, resp, edit)))
		})
	}
}

// The artifact binding is never accepted: resolving it would make the server
// call out.
func TestSAMLArtifactBindingRefused(t *testing.T) {
	f := newSAMLACSFixture(t)
	_, _ = f.respond(t, false, time.Now(), nil)
	r := newSAMLPost("SAMLart", "AAQAAMh48/1oXIM+sDo7Dh2qMp1HM4IF5DaRNmDj6RdUmllwn9jJHyEgIi8=")
	_, err := f.svc.ACS(context.Background(), "acme", samlACSBase, r, []string{f.requestID}, false)
	mustRefuse(t, err)
}

func TestSAMLReplayTTL(t *testing.T) {
	now := time.Now()
	short := &saml.Assertion{IssueInstant: now}
	if got := samlReplayTTL(short, now); got < saml.MaxIssueDelay+saml.MaxClockSkew {
		t.Fatalf("ttl %v shorter than the acceptance window", got)
	}
	long := &saml.Assertion{IssueInstant: now, Conditions: &saml.Conditions{NotOnOrAfter: now.Add(time.Hour)}}
	if got := samlReplayTTL(long, now); got < time.Hour {
		t.Fatalf("ttl %v ends before NotOnOrAfter", got)
	}
	huge := &saml.Assertion{IssueInstant: now, Conditions: &saml.Conditions{NotOnOrAfter: now.Add(30 * 24 * time.Hour)}}
	if got := samlReplayTTL(huge, now); got != samlReplayMaxTTL {
		t.Fatalf("ttl %v not capped", got)
	}
}

func TestMemorySAMLReplayStoreExpires(t *testing.T) {
	m := newMemorySAMLReplayStore()
	now := time.Now()
	m.now = func() time.Time { return now }
	if ok, _ := m.SetNX(context.Background(), "k", "1", time.Minute); !ok {
		t.Fatal("first insert must win")
	}
	if ok, _ := m.SetNX(context.Background(), "k", "1", time.Minute); ok {
		t.Fatal("second insert inside the TTL must lose")
	}
	now = now.Add(2 * time.Minute)
	if ok, _ := m.SetNX(context.Background(), "k", "1", time.Minute); !ok {
		t.Fatal("an expired entry must not block")
	}
}

func newSAMLPost(field, value string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acme/acs", strings.NewReader(url.Values{field: {value}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// A comment inside the signed NameID does not truncate it: canonicalization
// drops comments, so the signature still verifies, and the subject the
// service reads must be the whole value the IdP signed, never the text before
// the comment (the 2018 comment-injection class).
func TestSAMLNameIDCommentInjectionReadsWholeValue(t *testing.T) {
	f := newSAMLACSFixture(t)
	const signed = "owner@acme.com.evil.example"
	_, resp := f.respond(t, false, time.Now(), func(a *saml.IdpAuthnRequest) {
		a.Assertion.Subject.NameID.Value = signed
	})
	injected := editResponse(t, resp, func(root *etree.Element) {
		a := childByTag(root, "Assertion")
		nid := childByTag(childByTag(a, "Subject"), "NameID")
		if nid.Text() != signed {
			t.Fatalf("fixture NameID = %q", nid.Text())
		}
		nid.SetText("owner@acme.com")
		nid.CreateComment("x")
		nid.CreateText(".evil.example")
	})
	sp, rc, err := f.svc.resolveServiceProvider(context.Background(), "acme", samlACSBase)
	if err != nil {
		t.Fatal(err)
	}
	body := url.Values{"SAMLResponse": {injected}}.Encode()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acme/acs", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	a, err := f.svc.parseStrictResponse(context.Background(), sp, rc, r, []string{f.requestID})
	if err != nil {
		// The comment is outside the signed canonical form, so the response
		// still verifies; the test exists to check what is read from it.
		t.Fatalf("the commented response should still verify: %v", err)
	}
	if got := a.Subject.NameID.Value; got != signed {
		t.Fatalf("NameID read as %q, want the whole signed value %q", got, signed)
	}
}
