package email

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

// testCA makes a private CA and returns its PEM and a server certificate it
// signed for the given DNS name.
func testCA(t *testing.T, serverName string) (caPEM string, server tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test internal CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{serverName}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}
}

func TestParseCABundle(t *testing.T) {
	caPEM, _ := testCA(t, "mail.tenant.example")
	_, fp, err := ParseCABundle(caPEM + "\n" + caPEM)
	if err != nil || len(fp) != 64 {
		t.Fatalf("valid bundle: fp=%q err=%v", fp, err)
	}
	_, fp1, _ := ParseCABundle(caPEM)
	if fp1 == fp {
		t.Fatal("the fingerprint must cover every certificate")
	}

	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret-key-material")}))
	for name, in := range map[string]string{
		"empty":       "  ",
		"text":        "hello",
		"private key": caPEM + keyPEM,
		"trailing":    caPEM + "\nnot pem at all",
		"bad cert":    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})),
		"too many":    strings.Repeat(caPEM, MaxCACertificates+1),
		"too large":   strings.Repeat("A", MaxCABundleBytes+1),
	} {
		_, _, err := ParseCABundle(in)
		if !errors.Is(err, ErrInvalidCABundle) {
			t.Errorf("%s: err = %v, want ErrInvalidCABundle", name, err)
		}
		if err != nil && (strings.Contains(err.Error(), "secret-key-material") || strings.Contains(err.Error(), "hello")) {
			t.Errorf("%s: the error echoes the input: %v", name, err)
		}
	}
}

// The relay's certificate is verified against the internal CA when one is
// configured, and refused (with a precise reason) when it is not.
func TestSMTPSender_InternalCAVerification(t *testing.T) {
	const name = "mail.tenant.example"
	caPEM, cert := testCA(t, name)
	pool, _, err := ParseCABundle(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	_, otherCert := testCA(t, "other.tenant.example")

	serve := func(c tls.Certificate) string {
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					if tc := c.(*tls.Conn); tc.Handshake() == nil {
						_, _ = c.Write([]byte("554 no service\r\n"))
					}
				}()
			}
		}()
		return ln.Addr().String()
	}
	send := func(addr string, roots *x509.CertPool) error {
		stubNetwork(t,
			func(context.Context, string) (net.IP, error) { return net.ParseIP("203.0.113.9"), nil },
			func(ctx context.Context, _ time.Duration, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", addr)
			})
		return NewSMTPSender(Config{Host: name, Port: 465, From: "a@tenant.example", ImplicitTLS: true,
			RootCAs: roots, Timeout: 2 * time.Second}).Send(context.Background(), testMessage())
	}

	good := serve(cert)
	err = send(good, pool)
	if r := ClassifySendError(err); r == ReasonUnknownAuthority || r == ReasonHostnameMismatch || r == ReasonTLSFailed {
		t.Fatalf("with the CA the handshake must pass; got %q (%v)", r, err)
	}
	if r := ClassifySendError(send(good, nil)); r != ReasonUnknownAuthority {
		t.Fatalf("without the CA: %q, want %q", r, ReasonUnknownAuthority)
	}
	// A certificate for another name (and another CA) is refused.
	if r := ClassifySendError(send(serve(otherCert), pool)); r != ReasonUnknownAuthority && r != ReasonHostnameMismatch {
		t.Fatalf("wrong name / other CA: %q", r)
	}
	// The bundle replaces the system roots: another CA's bundle does not verify.
	otherPEM, _ := testCA(t, name)
	otherPool, _, _ := ParseCABundle(otherPEM)
	if r := ClassifySendError(send(good, otherPool)); r != ReasonUnknownAuthority {
		t.Fatalf("a bundle of another CA must not verify: %q", r)
	}
}

func TestClassifySendError(t *testing.T) {
	wrap := func(e error) error { return fmt.Errorf("%w: %w", ErrSendFailed, e) }
	for _, c := range []struct {
		err  error
		want string
	}{
		{nil, ""},
		{ErrNotConfigured, ReasonNotConfigured},
		{wrap(fmt.Errorf("failed to start TLS: %w", x509.UnknownAuthorityError{})), ReasonUnknownAuthority},
		{wrap(fmt.Errorf("failed to start TLS: %w", x509.HostnameError{Host: "h", Certificate: &x509.Certificate{}})), ReasonHostnameMismatch},
		{wrap(fmt.Errorf("failed to start TLS: %w", x509.CertificateInvalidError{Reason: x509.Expired})), ReasonCertInvalid},
		{wrap(errors.New("failed to start TLS: handshake failure")), ReasonTLSFailed},
		{wrap(fmt.Errorf("authentication failed: %w", &textproto.Error{Code: 535})), ReasonAuthFailed},
		{wrap(fmt.Errorf("failed to set recipient a@b: %w", &textproto.Error{Code: 554, Msg: "5.7.1 Relay access denied"})), ReasonRelayDenied},
		{wrap(fmt.Errorf("failed to set sender: %w", &textproto.Error{Code: 530})), ReasonAuthRequired},
		{wrap(fmt.Errorf("failed to set sender: %w", &textproto.Error{Code: 553})), ReasonSenderRejected},
		{wrap(errors.New("smtp host rejected: blocked")), ReasonHostRejected},
		{wrap(errors.New("failed to connect: refused")), ReasonConnectFailed},
		{wrap(errors.New("something else")), ReasonUnknown},
	} {
		if got := ClassifySendError(c.err); got != c.want {
			t.Errorf("%v: got %q want %q", c.err, got, c.want)
		}
	}
}
