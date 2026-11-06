package auth

import (
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/openctemio/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// respondWithAssertion returns a response whose assertion is the fixture's
// assertion after edit, signed by the IdP key, so the edit is covered by a
// valid signature (only the IdP signing-key holder can send such a response).
func (f *samlACSFixture) respondWithAssertion(t *testing.T, edit func(a *etree.Element)) string {
	t.Helper()
	_, resp := f.respond(t, false, time.Now(), func(authn *saml.IdpAuthnRequest) {
		el := authn.Assertion.Element()
		edit(el)
		keyStore := dsig.TLSCertKeyStore(tls.Certificate{
			Certificate: [][]byte{f.idp.Certificate.Raw}, PrivateKey: f.idp.Key, Leaf: f.idp.Certificate,
		})
		ctx := dsig.NewDefaultSigningContext(keyStore)
		ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
			t.Fatal(err)
		}
		signed, err := ctx.SignEnveloped(el)
		if err != nil {
			t.Fatal(err)
		}
		authn.AssertionEl = signed
	})
	return resp
}

// postNoPanic posts resp and fails the test if anything panics on the way.
func (f *samlACSFixture) postNoPanic(t *testing.T, resp string) (err error) {
	t.Helper()
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("the ACS panicked: %v", rec)
		}
	}()
	return f.post(resp)
}

func removeChildByTag(el *etree.Element, tag string) {
	if c := childByTag(el, tag); c != nil {
		el.RemoveChild(c)
	}
}

// The fixture's re-signed assertion is accepted as is, so every refusal below
// comes from the edit, not from the re-signing.
func TestSAMLResignedAssertionAccepted(t *testing.T) {
	f := newSAMLACSFixture(t)
	mustPass(t, f.postNoPanic(t, f.respondWithAssertion(t, func(*etree.Element) {})))
}

// GO-2026-6909 (1): a signed assertion without an Issuer is refused before
// the library reads it.
func TestSAMLAssertionWithoutIssuerRefused(t *testing.T) {
	f := newSAMLACSFixture(t)
	resp := f.respondWithAssertion(t, func(a *etree.Element) { removeChildByTag(a, "Issuer") })
	mustRefuse(t, f.postNoPanic(t, resp))
}

func TestSAMLAssertionIssuerShapeRefused(t *testing.T) {
	cases := map[string]func(a *etree.Element){
		"two issuers": func(a *etree.Element) {
			iss := childByTag(a, "Issuer").Copy()
			a.InsertChildAt(1, iss)
		},
		"foreign namespace issuer": func(a *etree.Element) {
			iss := childByTag(a, "Issuer")
			iss.Space = "x"
			iss.CreateAttr("xmlns:x", "urn:example:foreign")
		},
		"empty issuer": func(a *etree.Element) { childByTag(a, "Issuer").SetText(" ") },
		"issuer only nested": func(a *etree.Element) {
			iss := childByTag(a, "Issuer")
			a.RemoveChild(iss)
			childByTag(a, "Subject").AddChild(iss)
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSAMLACSFixture(t)
			mustRefuse(t, f.postNoPanic(t, f.respondWithAssertion(t, edit)))
		})
	}
}

// A signed assertion without Subject, Conditions or subject confirmation
// data made the library dereference a nil pointer.
func TestSAMLAssertionMissingRequiredElementsRefusedWithoutPanic(t *testing.T) {
	cases := map[string]func(a *etree.Element){
		"no subject":    func(a *etree.Element) { removeChildByTag(a, "Subject") },
		"no conditions": func(a *etree.Element) { removeChildByTag(a, "Conditions") },
		"no subject confirmation data": func(a *etree.Element) {
			removeChildByTag(childByTag(childByTag(a, "Subject"), "SubjectConfirmation"), "SubjectConfirmationData")
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSAMLACSFixture(t)
			mustRefuse(t, f.postNoPanic(t, f.respondWithAssertion(t, edit)))
		})
	}
}

// GO-2026-6909 (2): a NameID outside the assertion namespace would be read as
// the subject when the saml:NameID is absent.
func TestSAMLForeignNamespaceNameIDRefused(t *testing.T) {
	foreign := func(parent *etree.Element) {
		el := parent.CreateElement("x:NameID")
		el.CreateAttr("xmlns:x", "urn:example:foreign")
		el.SetText("owner@acme.com")
	}
	cases := map[string]func(a *etree.Element){
		"replaces the subject NameID": func(a *etree.Element) {
			subj := childByTag(a, "Subject")
			removeChildByTag(subj, "NameID")
			foreign(subj)
		},
		"next to the subject NameID": func(a *etree.Element) { foreign(childByTag(a, "Subject")) },
		"unqualified NameID": func(a *etree.Element) {
			subj := childByTag(a, "Subject")
			removeChildByTag(subj, "NameID")
			el := subj.CreateElement("NameID")
			el.CreateAttr("xmlns", "")
			el.SetText("owner@acme.com")
		},
		"in a subject confirmation": func(a *etree.Element) {
			foreign(childByTag(childByTag(a, "Subject"), "SubjectConfirmation"))
		},
		"foreign EncryptedID": func(a *etree.Element) {
			el := childByTag(a, "Subject").CreateElement("x:EncryptedID")
			el.CreateAttr("xmlns:x", "urn:example:foreign")
		},
		"foreign BaseID": func(a *etree.Element) {
			el := childByTag(a, "Subject").CreateElement("x:BaseID")
			el.CreateAttr("xmlns:x", "urn:example:foreign")
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSAMLACSFixture(t)
			mustRefuse(t, f.postNoPanic(t, f.respondWithAssertion(t, edit)))
		})
	}
}

func TestSAMLTwoSubjectIdentifiersRefused(t *testing.T) {
	f := newSAMLACSFixture(t)
	resp := f.respondWithAssertion(t, func(a *etree.Element) {
		subj := childByTag(a, "Subject")
		nid := childByTag(subj, "NameID").Copy()
		nid.SetText("other@acme.com")
		subj.InsertChildAt(0, nid)
	})
	mustRefuse(t, f.postNoPanic(t, resp))
}

// A panic inside the library parse is a refusal, never a crash.
func TestParseSAMLWithoutPanic(t *testing.T) {
	a, err := parseSAMLWithoutPanic(func() (*saml.Assertion, error) {
		panic("library bug")
	})
	if a != nil || !errors.Is(err, errSAMLStrict) {
		t.Fatalf("want a refusal, got %v, %v", a, err)
	}
	want := &saml.Assertion{ID: "a"}
	got, err := parseSAMLWithoutPanic(func() (*saml.Assertion, error) { return want, nil })
	if err != nil || got != want {
		t.Fatalf("a normal parse must pass through, got %v, %v", got, err)
	}
}

// The library also binds Conditions, Audience and SubjectConfirmationData by
// local name: a foreign one next to the real one would overwrite its values.
func TestSAMLForeignNamespaceConditionElementsRefused(t *testing.T) {
	foreign := func(parent *etree.Element, tag string) {
		el := parent.CreateElement("x:" + tag)
		el.CreateAttr("xmlns:x", "urn:example:foreign")
		el.CreateAttr("NotOnOrAfter", "2999-01-01T00:00:00Z")
	}
	cases := map[string]func(a *etree.Element){
		"conditions": func(a *etree.Element) { foreign(a, "Conditions") },
		"audience":   func(a *etree.Element) { foreign(childByTag(a, "Conditions"), "Audience") },
		"subject confirmation data": func(a *etree.Element) {
			foreign(childByTag(childByTag(a, "Subject"), "SubjectConfirmation"), "SubjectConfirmationData")
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSAMLACSFixture(t)
			mustRefuse(t, f.postNoPanic(t, f.respondWithAssertion(t, edit)))
		})
	}
}

// Without a subject confirmation the library checks neither the request
// binding nor the recipient.
func TestSAMLAssertionWithoutSubjectConfirmationRefused(t *testing.T) {
	f := newSAMLACSFixture(t)
	resp := f.respondWithAssertion(t, func(a *etree.Element) {
		removeChildByTag(childByTag(a, "Subject"), "SubjectConfirmation")
	})
	mustRefuse(t, f.postNoPanic(t, resp))
}
