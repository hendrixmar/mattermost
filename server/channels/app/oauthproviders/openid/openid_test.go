// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package openid

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/stretchr/testify/require"
)

func TestOpenIDProviderLoadsUnlicensedSettingsAndMapsVerifiedIdentity(t *testing.T) {
	server, signingKey := newOIDCTestServer(t, 1)
	defer server.Close()

	provider := &OpenIDProvider{}
	rctx := request.TestContext(t)
	settings, err := provider.GetSSOSettings(rctx, testOIDCConfig(server.URL), model.ServiceOpenid, server.Client())
	require.NoError(t, err)
	require.Equal(t, server.URL+"/authorize", *settings.AuthEndpoint)
	require.Equal(t, server.URL+"/token", *settings.TokenEndpoint)
	require.Equal(t, server.URL+"/userinfo", *settings.UserAPIEndpoint)

	token := signedIDToken(t, signingKey, "test-key", map[string]any{
		"iss":                server.URL,
		"sub":                "stable-subject-17",
		"email":              "person@example.com",
		"email_verified":     true,
		"preferred_username": "token-user",
	})
	tokenUser, err := provider.GetUserFromIdToken(rctx, token, settings, server.Client())
	require.NoError(t, err)
	require.Equal(t, "stable-subject-17", *tokenUser.AuthData)
	require.Equal(t, "person@example.com", tokenUser.Email)
	require.True(t, tokenUser.EmailVerified)

	userInfo := `{"sub":"stable-subject-17","email":"Person@Example.com","email_verified":true,"name":"Test Person","preferred_username":"preferred-user@example.com"}`
	user, err := provider.GetUserFromJSON(rctx, strings.NewReader(userInfo), tokenUser, settings)
	require.NoError(t, err)
	require.Equal(t, "stable-subject-17", *user.AuthData)
	require.Equal(t, "person@example.com", user.Email)
	require.True(t, user.EmailVerified)
	require.Equal(t, "preferred-user", user.Username)
	require.Equal(t, "Test", user.FirstName)
	require.Equal(t, "Person", user.LastName)
}

func TestOpenIDProviderAcceptsOmittedOptionalEmailVerification(t *testing.T) {
	server, signingKey := newOIDCTestServer(t, 5)
	defer server.Close()

	provider := &OpenIDProvider{}
	rctx := request.TestContext(t)
	settings, err := provider.GetSSOSettings(rctx, testOIDCConfig(server.URL), model.ServiceOpenid, server.Client())
	require.NoError(t, err)
	token := signedIDToken(t, signingKey, "test-key", map[string]any{
		"iss": server.URL, "sub": "company-subject", "email": "employee@example.com",
	})
	tokenUser, err := provider.GetUserFromIdToken(rctx, token, settings, server.Client())
	require.NoError(t, err)
	user, err := provider.GetUserFromJSON(rctx, strings.NewReader(`{"sub":"company-subject","email":"employee@example.com"}`), tokenUser, settings)
	require.NoError(t, err)
	require.Equal(t, "company-subject", *user.AuthData)
	require.Equal(t, "employee@example.com", user.Email)
	require.True(t, user.EmailVerified)
}

func TestOpenIDProviderRejectsInvalidIDTokens(t *testing.T) {
	server, signingKey := newOIDCTestServer(t, 2)
	defer server.Close()

	provider := &OpenIDProvider{}
	rctx := request.TestContext(t)
	settings, err := provider.GetSSOSettings(rctx, testOIDCConfig(server.URL), model.ServiceOpenid, server.Client())
	require.NoError(t, err)

	validClaims := map[string]any{
		"iss":            server.URL,
		"sub":            "stable-subject-17",
		"email":          "person@example.com",
		"email_verified": true,
	}
	otherSigningKey := deterministicSigningKey(3)
	testCases := []struct {
		name      string
		key       ed25519.PrivateKey
		audience  string
		issuer    string
		expiresAt time.Time
	}{
		{name: "expired", key: signingKey, audience: "client-id", issuer: server.URL, expiresAt: time.Now().Add(-time.Minute)},
		{name: "wrong audience", key: signingKey, audience: "another-client", issuer: server.URL, expiresAt: time.Now().Add(time.Hour)},
		{name: "wrong issuer", key: signingKey, audience: "client-id", issuer: server.URL + "/other", expiresAt: time.Now().Add(time.Hour)},
		{name: "bad signature", key: otherSigningKey, audience: "client-id", issuer: server.URL, expiresAt: time.Now().Add(time.Hour)},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := make(map[string]any, len(validClaims)+2)
			for name, value := range validClaims {
				claims[name] = value
			}
			claims["iss"] = tc.issuer
			claims["aud"] = tc.audience
			claims["exp"] = tc.expiresAt.Unix()
			claims["iat"] = time.Now().Add(-time.Minute).Unix()
			token := signedIDToken(t, tc.key, "test-key", claims)
			_, tokenErr := provider.GetUserFromIdToken(rctx, token, settings, server.Client())
			require.Error(t, tokenErr)
		})
	}
	_, err = provider.GetUserFromIdToken(rctx, "malformed", settings, server.Client())
	require.Error(t, err)
	unverified := signedIDToken(t, signingKey, "test-key", map[string]any{
		"iss": server.URL, "sub": "stable-subject-17",
		"email": "person@example.com", "email_verified": false,
	})
	_, err = provider.GetUserFromIdToken(rctx, unverified, settings, server.Client())
	require.Error(t, err)
}

func TestOpenIDProviderRejectsUnboundOrUnverifiedUserInfo(t *testing.T) {
	server, signingKey := newOIDCTestServer(t, 4)
	defer server.Close()

	provider := &OpenIDProvider{}
	rctx := request.TestContext(t)
	settings, err := provider.GetSSOSettings(rctx, testOIDCConfig(server.URL), model.ServiceOpenid, server.Client())
	require.NoError(t, err)
	token := signedIDToken(t, signingKey, "test-key", map[string]any{
		"iss":            server.URL,
		"sub":            "stable-subject-17",
		"email":          "person@example.com",
		"email_verified": true,
	})
	tokenUser, err := provider.GetUserFromIdToken(rctx, token, settings, server.Client())
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "mismatched subject", body: `{"sub":"other-subject","email":"person@example.com","email_verified":true}`},
		{name: "unverified email", body: `{"sub":"stable-subject-17","email":"person@example.com","email_verified":false}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, userErr := provider.GetUserFromJSON(rctx, strings.NewReader(tc.body), tokenUser, settings)
			require.Error(t, userErr)
		})
	}

	_, err = provider.GetUserFromJSON(rctx, strings.NewReader(`{"sub":"stable-subject-17","email":"person@example.com","email_verified":true}`), nil, settings)
	require.Error(t, err)
	minimalToken := signedIDToken(t, signingKey, "test-key", map[string]any{
		"iss": server.URL,
		"sub": "subject-from-user-info",
	})
	minimalTokenUser, err := provider.GetUserFromIdToken(rctx, minimalToken, settings, server.Client())
	require.NoError(t, err)
	user, err := provider.GetUserFromJSON(rctx, strings.NewReader(`{"sub":"subject-from-user-info","email":"profile@example.com","email_verified":true}`), minimalTokenUser, settings)
	require.NoError(t, err)
	require.Equal(t, "subject-from-user-info", *user.AuthData)
	require.Equal(t, "profile", user.Username)
}

func TestOpenIDProviderVerifiesRSAAndECDSATokens(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, testCase := range []struct {
		method jwt.SigningMethod
		key    any
		jwk    jwk
	}{
		{jwt.SigningMethodRS256, rsaKey, jwk{
			KeyType: "RSA",
			N:       base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
			E:       base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
		}},
		{jwt.SigningMethodES256, ecKey, jwk{
			KeyType: "EC",
			Curve:   "P-256",
			X:       base64.RawURLEncoding.EncodeToString(ecKey.X.FillBytes(make([]byte, 32))),
			Y:       base64.RawURLEncoding.EncodeToString(ecKey.Y.FillBytes(make([]byte, 32))),
		}},
	} {
		t.Run(testCase.method.Alg(), func(t *testing.T) {
			server := newOIDCServer(t, jwkSet{Keys: []jwk{testCase.jwk}})
			defer server.Close()
			provider := &OpenIDProvider{}
			rctx := request.TestContext(t)
			settings, settingsErr := provider.GetSSOSettings(rctx, testOIDCConfig(server.URL), model.ServiceOpenid, server.Client())
			require.NoError(t, settingsErr)
			token := jwt.NewWithClaims(testCase.method, jwt.MapClaims{
				"iss": server.URL, "aud": "client-id", "sub": "rsa-or-ec-subject",
				"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
				"email": "person@example.com", "email_verified": true,
			})
			encoded, signErr := token.SignedString(testCase.key)
			require.NoError(t, signErr)

			user, tokenErr := provider.GetUserFromIdToken(rctx, encoded, settings, server.Client())
			require.NoError(t, tokenErr)
			require.Equal(t, "rsa-or-ec-subject", *user.AuthData)
			require.Equal(t, "person@example.com", user.Email)
		})
	}
}

func newOIDCTestServer(t *testing.T, seedByte byte) (*httptest.Server, ed25519.PrivateKey) {
	t.Helper()
	privateKey := deterministicSigningKey(seedByte)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keySet := jwkSet{Keys: []jwk{{
		KeyType: "OKP",
		KeyID:   "test-key",
		Use:     "sig",
		Alg:     jwt.SigningMethodEdDSA.Alg(),
		Curve:   "Ed25519",
		X:       base64.RawURLEncoding.EncodeToString(publicKey),
	}}}
	return newOIDCServer(t, keySet), privateKey
}

func newOIDCServer(t *testing.T, keySet jwkSet) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(discoveryDocument{
				Issuer:                serverURL(r),
				AuthorizationEndpoint: serverURL(r) + "/authorize",
				TokenEndpoint:         serverURL(r) + "/token",
				UserInfoEndpoint:      serverURL(r) + "/userinfo",
				JWKSURI:               serverURL(r) + "/jwks",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(keySet)
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}

func serverURL(r *http.Request) string {
	return "http://" + r.Host
}

func testOIDCConfig(serverURL string) *model.Config {
	return &model.Config{OpenIdSettings: model.SSOSettings{
		Enable:               new(true),
		Id:                   new("client-id"),
		Secret:               new("client-secret"),
		Scope:                new("openid profile email"),
		DiscoveryEndpoint:    new(serverURL + "/.well-known/openid-configuration"),
		UsePreferredUsername: new(true),
	}}
}

func deterministicSigningKey(seedByte byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte + byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func signedIDToken(t *testing.T, signingKey ed25519.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	if _, exists := claims["exp"]; !exists {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, exists := claims["iat"]; !exists {
		claims["iat"] = time.Now().Add(-time.Minute).Unix()
	}
	if _, exists := claims["aud"]; !exists {
		claims["aud"] = "client-id"
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims(claims))
	token.Header["kid"] = keyID
	encoded, err := token.SignedString(signingKey)
	require.NoError(t, err)
	return encoded
}
