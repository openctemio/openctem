package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/oidc"
)

const googleTestClientID = "google-client.apps.example.com"

// googleSocialFixture is the social Google sign-in with Google's JWKS and
// userinfo endpoints answered by local servers.
type googleSocialFixture struct {
	svc       *OAuthService
	key       *rsa.PrivateKey
	profileID string
}

func newGoogleSocialFixture(t *testing.T) *googleSocialFixture {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &googleSocialFixture{key: key, profileID: "g-sub-1"}
	jwks := jwksServer(t, &key.PublicKey)
	t.Cleanup(jwks.Close)
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": f.profileID, "name": "Ada", "picture": "https://example.com/a.png"})
	}))
	t.Cleanup(profile.Close)
	route := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case googleJWKSURL:
			return http.Get(jwks.URL) //nolint:noctx // test transport
		case "https://www.googleapis.com/oauth2/v2/userinfo":
			return http.Get(profile.URL) //nolint:noctx // test transport
		}
		return nil, errors.New("unexpected request to " + r.URL.String())
	})
	cfg := config.OAuthConfig{Google: config.OAuthProviderConfig{Enabled: true, ClientID: googleTestClientID}}
	f.svc = NewOAuthService(nil, nil, nil, cfg, config.AuthConfig{JWTSecret: "jwt-secret-for-tests-0123456789abcdef"}, logger.NewNop())
	client := &http.Client{Transport: route, Timeout: 5 * time.Second}
	f.svc.httpClient = client
	f.svc.oidcVerifier = oidc.NewClient(client, nil)
	return f
}

func googleClaims() oidc.Claims {
	return oidc.Claims{
		Email:         "ada@example.com",
		EmailVerified: true,
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:    "https://accounts.google.com",
			Subject:   "g-sub-1",
			Audience:  jwtv5.ClaimStrings{googleTestClientID},
			ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(time.Now()),
		},
	}
}

func (f *googleSocialFixture) signed(t *testing.T, m jwtv5.SigningMethod, c oidc.Claims) string {
	t.Helper()
	tok := jwtv5.NewWithClaims(m, c)
	tok.Header["kid"] = testKID
	s, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Social Google sign-in takes the identity from the verified id_token.
func TestGoogleSocialLogin_IdentityFromVerifiedIDToken(t *testing.T) {
	f := newGoogleSocialFixture(t)
	info, err := f.svc.getGoogleUserInfo(context.Background(),
		&oauthTokens{AccessToken: "at", IDToken: f.signed(t, jwtv5.SigningMethodRS256, googleClaims())})
	if err != nil {
		t.Fatalf("valid Google id_token refused: %v", err)
	}
	if info.Subject != "g-sub-1" || info.Issuer != googleIssuer || info.Email != "ada@example.com" ||
		info.Name != "Ada" || info.AvatarURL == "" {
		t.Fatalf("unexpected identity: %+v", info)
	}
}

// T4/T5/T6: every Google login without a valid id_token for our client is
// refused.
func TestGoogleSocialLogin_Refusals(t *testing.T) {
	cases := map[string]func(f *googleSocialFixture, t *testing.T) *oauthTokens{
		"TestIDTokenMissingRefused": func(*googleSocialFixture, *testing.T) *oauthTokens {
			return &oauthTokens{AccessToken: "at"}
		},
		"email not verified": func(f *googleSocialFixture, t *testing.T) *oauthTokens {
			c := googleClaims()
			c.EmailVerified = false
			return &oauthTokens{AccessToken: "at", IDToken: f.signed(t, jwtv5.SigningMethodRS256, c)}
		},
		"another client's id_token": func(f *googleSocialFixture, t *testing.T) *oauthTokens {
			c := googleClaims()
			c.Audience = jwtv5.ClaimStrings{"other-client"}
			return &oauthTokens{AccessToken: "at", IDToken: f.signed(t, jwtv5.SigningMethodRS256, c)}
		},
		"TestIDTokenWrongAzpRefused": func(f *googleSocialFixture, t *testing.T) *oauthTokens {
			c := googleClaims()
			c.Audience = jwtv5.ClaimStrings{googleTestClientID, "other-client"}
			c.AZP = "other-client"
			return &oauthTokens{AccessToken: "at", IDToken: f.signed(t, jwtv5.SigningMethodRS256, c)}
		},
		"foreign issuer": func(f *googleSocialFixture, t *testing.T) *oauthTokens {
			c := googleClaims()
			c.Issuer = "https://idp.example.com"
			return &oauthTokens{AccessToken: "at", IDToken: f.signed(t, jwtv5.SigningMethodRS256, c)}
		},
		"RS512 outside the allow-list": func(f *googleSocialFixture, t *testing.T) *oauthTokens {
			return &oauthTokens{AccessToken: "at", IDToken: f.signed(t, jwtv5.SigningMethodRS512, googleClaims())}
		},
		"TestIDTokenHS256Refused": func(f *googleSocialFixture, t *testing.T) *oauthTokens {
			tok := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, googleClaims())
			tok.Header["kid"] = testKID
			s, _ := tok.SignedString([]byte("client-secret"))
			return &oauthTokens{AccessToken: "at", IDToken: s}
		},
		"userinfo for another account": func(f *googleSocialFixture, t *testing.T) *oauthTokens {
			f.profileID = "g-sub-other"
			return &oauthTokens{AccessToken: "at", IDToken: f.signed(t, jwtv5.SigningMethodRS256, googleClaims())}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			f := newGoogleSocialFixture(t)
			if info, err := f.svc.getGoogleUserInfo(context.Background(), mk(f, t)); err == nil {
				t.Fatalf("must be refused, got %+v", info)
			}
		})
	}
}
