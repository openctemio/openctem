package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

// An assertion signed by the IdP key but outside the Web Browser SSO profile
// is refused: missing or foreign audience, a non-bearer confirmation, an issue
// time in the future, or a statement in another namespace.
func TestSAMLAssertionProfileRefused(t *testing.T) {
	cases := map[string]func(a *etree.Element){
		"no audience restriction": func(a *etree.Element) {
			removeChildByTag(childByTag(a, "Conditions"), "AudienceRestriction")
		},
		"a second restriction for another service": func(a *etree.Element) {
			ar := childByTag(a, "Conditions").CreateElement("saml:AudienceRestriction")
			ar.CreateElement("saml:Audience").SetText("https://other.example.com/metadata")
		},
		"holder-of-key confirmation": func(a *etree.Element) {
			sc := childByTag(childByTag(a, "Subject"), "SubjectConfirmation")
			sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key")
		},
		"issued a day ahead": func(a *etree.Element) {
			a.CreateAttr("IssueInstant", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339))
		},
		"attribute statement in another namespace": func(a *etree.Element) {
			st := a.CreateElement("x:AttributeStatement")
			st.CreateAttr("xmlns:x", "urn:example:foreign")
			at := st.CreateElement("x:Attribute")
			at.CreateAttr("Name", samlEntraObjectIDAttr)
			at.CreateElement("x:AttributeValue").SetText("someone-else")
		},
		"authn statement in another namespace": func(a *etree.Element) {
			st := a.CreateElement("x:AuthnStatement")
			st.CreateAttr("xmlns:x", "urn:example:foreign")
			st.CreateAttr("AuthnInstant", time.Now().UTC().Format(time.RFC3339))
			st.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText("https://refeds.org/profile/mfa")
		},
		"attribute value in another namespace": func(a *etree.Element) {
			st := a.CreateElement("saml:AttributeStatement")
			at := st.CreateElement("saml:Attribute")
			at.CreateAttr("Name", "email")
			v := at.CreateElement("x:AttributeValue")
			v.CreateAttr("xmlns:x", "urn:example:foreign")
			v.SetText("owner@acme.com")
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSAMLACSFixture(t)
			mustRefuse(t, f.postNoPanic(t, f.respondWithAssertion(t, edit)))
		})
	}
}

// The checks accept what conforming IdPs send: a second restriction that also
// names this service provider, and an explicit bearer method.
func TestSAMLAssertionProfileAccepted(t *testing.T) {
	cases := map[string]func(a *etree.Element){
		"two restrictions both naming this service": func(a *etree.Element) {
			c := childByTag(a, "Conditions")
			c.AddChild(childByTag(c, "AudienceRestriction").Copy())
		},
		"bearer confirmation": func(a *etree.Element) {
			sc := childByTag(childByTag(a, "Subject"), "SubjectConfirmation")
			sc.CreateAttr("Method", samlBearerMethod)
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSAMLACSFixture(t)
			mustPass(t, f.postNoPanic(t, f.respondWithAssertion(t, edit)))
		})
	}
}

// Unsigned parts of a response cannot change how the signed assertion is
// read: a prefix bound to a second namespace anywhere is refused, and so is a
// document type declaration.
func TestSAMLResponseDocumentRefused(t *testing.T) {
	t.Run("prefix bound twice", func(t *testing.T) {
		f := newSAMLACSFixture(t)
		_, resp := f.respond(t, false, time.Now(), nil)
		edited := editResponse(t, resp, func(root *etree.Element) {
			el := root.CreateElement("saml:Note")
			el.CreateAttr("xmlns:saml", "urn:example:foreign")
		})
		mustRefuse(t, f.postNoPanic(t, edited))
	})
	t.Run("document type declaration", func(t *testing.T) {
		f := newSAMLACSFixture(t)
		_, resp := f.respond(t, false, time.Now(), nil)
		raw, _ := base64.StdEncoding.DecodeString(resp)
		s := string(raw)
		if strings.HasPrefix(s, "<?xml") {
			s = s[strings.Index(s, "?>")+2:]
		}
		s = `<!DOCTYPE Response [<!ENTITY e "x">]>` + s
		mustRefuse(t, f.postNoPanic(t, base64.StdEncoding.EncodeToString([]byte(s))))
	})
}

func TestCheckSAMLNamespacePrefixes(t *testing.T) {
	ok := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/>` +
		`<Subject/></Assertion><saml:X xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/></samlp:Response>`
	bad := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<x:A xmlns:x="urn:a"/><x:B xmlns:x="urn:b"/></samlp:Response>`
	for doc, wantErr := range map[string]bool{ok: false, bad: true} {
		d := etree.NewDocument()
		if err := d.ReadFromString(doc); err != nil {
			t.Fatal(err)
		}
		if err := checkSAMLNamespacePrefixes(d.Root()); (err != nil) != wantErr {
			t.Fatalf("%s: err=%v", doc, err)
		}
	}
}
