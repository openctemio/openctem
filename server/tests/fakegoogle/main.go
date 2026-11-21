// Command fakegoogle is a test-only stand-in for Google's sign-in endpoints,
// for the end-to-end stack (web/e2e/ci/fake-google.compose.yml). The API
// binary under test is unchanged: the stack gives this server the network
// names oauth2.googleapis.com, www.googleapis.com and accounts.google.com,
// and the API trusts the certificate authority this server writes (and only
// it) through SSL_CERT_FILE. Never run it anywhere else.
//
// The authorization code names the identity to sign in as:
// base64url(JSON {"sub","email","name","hd"}), which the browser test puts in the
// redirect it answers for accounts.google.com. The token endpoint answers an
// RS256 id_token for that identity (issuer https://accounts.google.com,
// audience FAKE_GOOGLE_CLIENT_ID, email verified), the JWKS endpoint serves
// the key, and userinfo describes the same subject.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

type identity struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
	// HD is the Workspace domain claim; set it to the address's domain for a
	// Workspace account (whose address the provider vouches for).
	HD string `json:"hd,omitempty"`
}

const keyID = "fake-google-1"

func decodeIdentity(s string) (identity, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return identity{}, false
	}
	var id identity
	if json.Unmarshal(raw, &id) != nil || id.Sub == "" || id.Email == "" {
		return identity{}, false
	}
	return id, true
}

func main() {
	clientID := os.Getenv("FAKE_GOOGLE_CLIENT_ID")
	caOut := os.Getenv("FAKE_GOOGLE_CA_OUT")
	addr := os.Getenv("FAKE_GOOGLE_ADDR")
	if clientID == "" || caOut == "" {
		log.Fatal("FAKE_GOOGLE_CLIENT_ID and FAKE_GOOGLE_CA_OUT are required")
	}
	if addr == "" {
		addr = ":443"
	}

	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	cert, caPEM, err := newServerCert([]string{"oauth2.googleapis.com", "www.googleapis.com", "accounts.google.com"})
	if err != nil {
		log.Fatal(err)
	}
	// A public certificate the API process (another user) reads.
	if err := os.WriteFile(caOut, caPEM, 0o644); err != nil { //nolint:gosec // public CA certificate
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		id, ok := decodeIdentity(r.PostForm.Get("code"))
		if !ok || r.PostForm.Get("client_id") != clientID {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		now := time.Now()
		claims := jwtv5.MapClaims{
			"iss": "https://accounts.google.com", "aud": clientID, "sub": id.Sub,
			"email": id.Email, "email_verified": true, "name": id.Name,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		}
		if id.HD != "" {
			claims["hd"] = id.HD
		}
		tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, claims)
		tok.Header["kid"] = keyID
		idToken, err := tok.SignedString(signing)
		if err != nil {
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": r.PostForm.Get("code"), "id_token": idToken,
			"token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("GET /oauth2/v3/certs", func(w http.ResponseWriter, _ *http.Request) {
		pub := signing.PublicKey
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": keyID,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("GET /oauth2/v2/userinfo", func(w http.ResponseWriter, r *http.Request) {
		id, ok := decodeIdentity(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id.Sub, "email": id.Email, "verified_email": true, "name": id.Name})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Print("fake google listening")
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// newServerCert makes a throwaway certificate authority and a server
// certificate for names, signed by it. It returns the server certificate and
// the authority's PEM.
func newServerCert(names []string) (tls.Certificate, []byte, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake google test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		DNSNames: names, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, caPEM, nil
}
