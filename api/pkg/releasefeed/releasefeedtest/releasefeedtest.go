// Package releasefeedtest signs release feeds with a virtual Sigstore (own
// certificate authority, transparency log and timestamp authority), so tests
// exercise the real offline verification without Sigstore or the network. It
// is test support only: nothing in a production binary imports it, and no
// fixture here is accepted by the embedded trusted root.
package releasefeedtest

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	cpsigstore "github.com/openctemio/openctem/api/pkg/contentpkg/sigstore"
)

// Workflow identities the real publisher has, and ones it does not.
const (
	GoodIdentityMain = "https://github.com/openctemio/openctem/.github/workflows/release-feed.yml@refs/heads/main"
	GoodIdentityTag  = "https://github.com/openctemio/openctem/.github/workflows/release-feed.yml@refs/tags/v1.2.3"
	GitHubIssuer     = "https://token.actions.githubusercontent.com"
)

// Sigstore is one virtual Sigstore.
type Sigstore struct {
	vs *ca.VirtualSigstore
}

// New creates a virtual Sigstore.
func New(t testing.TB) *Sigstore {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	return &Sigstore{vs: vs}
}

// Verifier is the production verifier trusting only this virtual Sigstore.
func (s *Sigstore) Verifier(t testing.TB) *cpsigstore.Verifier {
	t.Helper()
	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		s.vs.FulcioCertificateAuthorities(), s.vs.CTLogs(), s.vs.TimestampingAuthorities(), s.vs.RekorLogs())
	if err != nil {
		t.Fatal(err)
	}
	v, err := cpsigstore.NewFromTrustedRoot(tr)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Sign returns the Sigstore bundle JSON over artifact, as cosign writes it,
// signed at integrated with the given identity and issuer. withoutTlog drops
// the transparency log entry from the bundle.
func (s *Sigstore) Sign(t testing.TB, artifact []byte, identity, issuer string, integrated time.Time, withoutTlog bool) []byte {
	t.Helper()
	e, err := s.vs.SignAtTime(identity, issuer, artifact, integrated)
	if err != nil {
		t.Fatal(err)
	}
	vc, err := e.VerificationContent()
	if err != nil {
		t.Fatal(err)
	}
	cert := vc.Certificate()
	sc, err := e.SignatureContent()
	if err != nil {
		t.Fatal(err)
	}
	ms := sc.MessageSignatureContent()
	entries, err := e.TlogEntries()
	if err != nil {
		t.Fatal(err)
	}
	tsrs, err := e.Timestamps()
	if err != nil {
		t.Fatal(err)
	}
	b := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: certContent(cert),
		},
		Content: &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: ms.Digest()},
			Signature:     ms.Signature(),
		}},
	}
	if !withoutTlog {
		for _, en := range entries {
			b.VerificationMaterial.TlogEntries = append(b.VerificationMaterial.TlogEntries, s.serialisable(t, en.TransparencyLogEntry()))
		}
	}
	tv := &protobundle.TimestampVerificationData{}
	for _, r := range tsrs {
		tv.Rfc3161Timestamps = append(tv.Rfc3161Timestamps, &protocommon.RFC3161SignedTimestamp{SignedTimestamp: r})
	}
	b.VerificationMaterial.TimestampVerificationData = tv
	out, err := protojson.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// serialisable adds what the virtual log keeps outside the entry: the kind
// and version, and the signed entry timestamp the real log returns.
func (s *Sigstore) serialisable(t testing.TB, in *protorekor.TransparencyLogEntry) *protorekor.TransparencyLogEntry {
	t.Helper()
	tle := proto.Clone(in).(*protorekor.TransparencyLogEntry)
	tle.KindVersion = &protorekor.KindVersion{Kind: "hashedrekord", Version: "0.0.1"}
	set, err := s.vs.RekorSignPayload(tlog.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(tle.CanonicalizedBody),
		IntegratedTime: tle.IntegratedTime,
		LogIndex:       tle.LogIndex,
		LogID:          hex.EncodeToString(tle.LogId.KeyId),
	})
	if err != nil {
		t.Fatal(err)
	}
	tle.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
	return tle
}

func certContent(c *x509.Certificate) *protobundle.VerificationMaterial_X509CertificateChain {
	return &protobundle.VerificationMaterial_X509CertificateChain{X509CertificateChain: &protocommon.X509CertificateChain{
		Certificates: []*protocommon.X509Certificate{{RawBytes: c.Raw}}}}
}
