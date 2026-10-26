// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package openid

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
)

const maxOIDCResponseSize = 1 << 20

const googleDiscoveryEndpoint = "https://accounts.google.com/.well-known/openid-configuration"

type OpenIDProvider struct{}

type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type idTokenClaims struct {
	jwt.RegisteredClaims
	Email             string `json:"email"`
	EmailVerified     *bool  `json:"email_verified"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	Nickname          string `json:"nickname"`
	PreferredUsername string `json:"preferred_username"`
	Username          string `json:"username"`
	AuthorizedParty   string `json:"azp"`
	TenantID          string `json:"tid"`
}

type userInfo struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     *bool  `json:"email_verified"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	Nickname          string `json:"nickname"`
	PreferredUsername string `json:"preferred_username"`
	Username          string `json:"username"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KeyType string   `json:"kty"`
	KeyID   string   `json:"kid"`
	Use     string   `json:"use"`
	KeyOps  []string `json:"key_ops"`
	Alg     string   `json:"alg"`
	N       string   `json:"n"`
	E       string   `json:"e"`
	Curve   string   `json:"crv"`
	X       string   `json:"x"`
	Y       string   `json:"y"`
	D       string   `json:"d"`
}

func init() {
	einterfaces.RegisterOAuthProvider(model.ServiceOpenid, &OpenIDProvider{})
}

func (p *OpenIDProvider) GetSSOSettings(rctx request.CTX, config *model.Config, service string, client *http.Client) (*model.SSOSettings, error) {
	if config == nil {
		return nil, errors.New("OIDC configuration is missing")
	}

	configured := config.GetSSOService(service)
	if configured == nil {
		return nil, fmt.Errorf("no SSO settings for service %q", service)
	}

	settings := *configured
	if !model.HasOpenIDScope(value(settings.Scope)) {
		return nil, errors.New("OIDC scope is required")
	}

	discoveryEndpoint, err := configuredDiscoveryEndpoint(config, service, &settings)
	if err != nil {
		return nil, err
	}
	metadata, err := fetchDiscovery(rctx.Context(), client, discoveryEndpoint)
	if err != nil {
		return nil, err
	}

	settings.DiscoveryEndpoint = new(discoveryEndpoint)
	if value(settings.AuthEndpoint) == "" {
		settings.AuthEndpoint = new(metadata.AuthorizationEndpoint)
	}
	if value(settings.TokenEndpoint) == "" {
		settings.TokenEndpoint = new(metadata.TokenEndpoint)
	}
	settings.UserAPIEndpoint = new(metadata.UserInfoEndpoint)

	for _, endpoint := range []*string{settings.AuthEndpoint, settings.TokenEndpoint, settings.UserAPIEndpoint} {
		if endpoint == nil || *endpoint == "" {
			return nil, errors.New("OIDC discovery is missing a required endpoint")
		}
		if err = validateEndpoint(*endpoint); err != nil {
			return nil, errors.New("OIDC discovery contains an invalid endpoint")
		}
	}

	return &settings, nil
}

func (p *OpenIDProvider) GetUserFromIdToken(rctx request.CTX, idToken string, settings *model.SSOSettings, client *http.Client) (*model.User, error) {
	if settings == nil || idToken == "" || len(idToken) > 64<<10 {
		return nil, errors.New("invalid OIDC ID token")
	}
	clientID := value(settings.Id)
	if clientID == "" {
		return nil, errors.New("OIDC client ID is required")
	}

	metadata, err := fetchDiscovery(rctx.Context(), client, value(settings.DiscoveryEndpoint))
	if err != nil {
		return nil, err
	}
	var keys jwkSet
	if err = fetchJSON(rctx.Context(), client, metadata.JWKSURI, &keys); err != nil {
		return nil, errors.New("unable to retrieve OIDC signing keys")
	}

	claims := &idTokenClaims{}
	parsed, err := jwt.ParseWithClaims(idToken, claims, func(token *jwt.Token) (any, error) {
		return verificationKey(token, keys)
	}, jwt.WithValidMethods([]string{
		jwt.SigningMethodRS256.Alg(), jwt.SigningMethodRS384.Alg(), jwt.SigningMethodRS512.Alg(),
		jwt.SigningMethodPS256.Alg(), jwt.SigningMethodPS384.Alg(), jwt.SigningMethodPS512.Alg(),
		jwt.SigningMethodES256.Alg(), jwt.SigningMethodES384.Alg(), jwt.SigningMethodES512.Alg(),
		jwt.SigningMethodEdDSA.Alg(),
	}), jwt.WithAudience(clientID), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || parsed == nil || !parsed.Valid {
		return nil, errors.New("invalid OIDC ID token")
	}
	if claims.Issuer == "" || claims.Subject == "" || claims.IssuedAt == nil || claims.ExpiresAt == nil || !contains(claims.Audience, clientID) {
		return nil, errors.New("OIDC ID token is missing required claims")
	}
	if claims.AuthorizedParty != "" && claims.AuthorizedParty != clientID || len(claims.Audience) > 1 && claims.AuthorizedParty != clientID {
		return nil, errors.New("OIDC ID token audience is invalid")
	}
	if !issuerMatches(metadata.Issuer, claims.Issuer, claims.TenantID) {
		return nil, errors.New("OIDC ID token issuer is invalid")
	}
	// The configured issuer is the email authority when it omits this optional claim.
	if claims.Email != "" && claims.EmailVerified != nil && !*claims.EmailVerified {
		return nil, errors.New("OIDC ID token email is not verified")
	}

	profile := userInfo{
		Email:             claims.Email,
		EmailVerified:     claims.EmailVerified,
		Name:              claims.Name,
		GivenName:         claims.GivenName,
		FamilyName:        claims.FamilyName,
		Nickname:          claims.Nickname,
		PreferredUsername: claims.PreferredUsername,
		Username:          claims.Username,
	}
	user, err := mapOIDCUser(rctx, profile, nil, claims.Subject, settings)
	if err != nil {
		return nil, err
	}
	user.Email = strings.ToLower(strings.TrimSpace(claims.Email))
	user.EmailVerified = claims.Email != ""
	return user, nil
}

func (p *OpenIDProvider) GetUserFromJSON(rctx request.CTX, data io.Reader, tokenUser *model.User, settings *model.SSOSettings) (*model.User, error) {
	if tokenUser == nil || tokenUser.AuthData == nil || *tokenUser.AuthData == "" {
		return nil, errors.New("a verified OIDC ID token is required")
	}
	if settings == nil {
		return nil, errors.New("OIDC settings are missing")
	}
	if tokenUser.Email != "" && !tokenUser.EmailVerified {
		return nil, errors.New("OIDC ID token email is not verified")
	}
	if data == nil {
		return nil, errors.New("invalid OIDC user info response")
	}

	body, err := io.ReadAll(io.LimitReader(data, maxOIDCResponseSize+1))
	if err != nil || len(body) > maxOIDCResponseSize {
		return nil, errors.New("invalid OIDC user info response")
	}
	var claims userInfo
	if err = json.Unmarshal(body, &claims); err != nil {
		return nil, errors.New("invalid OIDC user info response")
	}
	if claims.Subject == "" || claims.Subject != *tokenUser.AuthData {
		return nil, errors.New("OIDC user info subject does not match the verified ID token")
	}

	email := ""
	if claims.Email != "" {
		if claims.EmailVerified != nil && !*claims.EmailVerified {
			return nil, errors.New("OIDC user info email is not verified")
		}
		email = claims.Email
		if tokenUser.Email != "" && !strings.EqualFold(strings.TrimSpace(tokenUser.Email), strings.TrimSpace(email)) {
			return nil, errors.New("OIDC email claims do not match")
		}
	} else if tokenUser.Email != "" && tokenUser.EmailVerified {
		email = tokenUser.Email
	}
	if email == "" {
		return nil, errors.New("OIDC email is required")
	}

	user, err := mapOIDCUser(rctx, claims, tokenUser, *tokenUser.AuthData, settings)
	if err != nil {
		return nil, err
	}
	if user.Username == "" {
		return nil, errors.New("OIDC username is required")
	}
	user.Email = strings.ToLower(strings.TrimSpace(email))
	user.EmailVerified = true
	return user, nil
}

func (p *OpenIDProvider) IsSameUser(_ request.CTX, dbUser, oauthUser *model.User) bool {
	return dbUser != nil && oauthUser != nil && dbUser.AuthData != nil && oauthUser.AuthData != nil &&
		dbUser.AuthService == oauthUser.AuthService && *dbUser.AuthData != "" && *dbUser.AuthData == *oauthUser.AuthData
}

func value(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func configuredDiscoveryEndpoint(config *model.Config, service string, settings *model.SSOSettings) (string, error) {
	if endpoint := value(settings.DiscoveryEndpoint); endpoint != "" {
		return endpoint, nil
	}

	switch service {
	case model.ServiceGoogle:
		return googleDiscoveryEndpoint, nil
	case model.ServiceOffice365:
		tenant := value(config.Office365Settings.DirectoryId)
		if tenant == "" {
			tenant = "common"
		}
		if strings.ContainsAny(tenant, "/?#") {
			return "", errors.New("invalid Office365 directory ID")
		}
		return "https://login.microsoftonline.com/" + url.PathEscape(tenant) + "/v2.0/.well-known/openid-configuration", nil
	case model.ServiceGitlab:
		authorizationURL, err := url.Parse(value(settings.AuthEndpoint))
		if err != nil || authorizationURL.Scheme == "" || authorizationURL.Host == "" {
			return "", errors.New("OIDC discovery endpoint is required")
		}
		authorizationURL.Path = "/.well-known/openid-configuration"
		authorizationURL.RawPath = ""
		authorizationURL.RawQuery = ""
		authorizationURL.Fragment = ""
		return authorizationURL.String(), nil
	default:
		return "", errors.New("OIDC discovery endpoint is required")
	}
}

func fetchDiscovery(ctx context.Context, client *http.Client, endpoint string) (discoveryDocument, error) {
	var metadata discoveryDocument
	if err := fetchJSON(ctx, client, endpoint, &metadata); err != nil {
		return discoveryDocument{}, errors.New("unable to retrieve OIDC discovery document")
	}
	if metadata.Issuer == "" || metadata.JWKSURI == "" || metadata.UserInfoEndpoint == "" ||
		validateIssuer(metadata.Issuer) != nil || validateEndpoint(metadata.JWKSURI) != nil || validateEndpoint(metadata.UserInfoEndpoint) != nil {
		return discoveryDocument{}, errors.New("OIDC discovery document is missing required metadata")
	}
	if metadata.AuthorizationEndpoint != "" && validateEndpoint(metadata.AuthorizationEndpoint) != nil {
		return discoveryDocument{}, errors.New("OIDC discovery document contains an invalid authorization endpoint")
	}
	if metadata.TokenEndpoint != "" && validateEndpoint(metadata.TokenEndpoint) != nil {
		return discoveryDocument{}, errors.New("OIDC discovery document contains an invalid token endpoint")
	}
	return metadata, nil
}

func validateIssuer(issuer string) error {
	if err := validateEndpoint(issuer); err != nil {
		return err
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("invalid OIDC issuer")
	}
	return nil
}

func validateEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return errors.New("invalid OIDC endpoint")
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return errors.New("OIDC endpoints must use HTTPS")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	return strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") || func() bool {
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	}()
}

func fetchJSON(ctx context.Context, client *http.Client, endpoint string, target any) error {
	if client == nil || validateEndpoint(endpoint) != nil {
		return errors.New("invalid OIDC HTTP request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("invalid OIDC HTTP request")
	}
	request.Header.Set("Accept", "application/json")

	response, err := oidcHTTPClient(client).Do(request)
	if err != nil {
		return errors.New("OIDC endpoint request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("OIDC endpoint returned a non-success status")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxOIDCResponseSize+1))
	if err != nil || len(body) > maxOIDCResponseSize {
		return errors.New("OIDC endpoint response is invalid")
	}
	if err = json.Unmarshal(body, target); err != nil {
		return errors.New("OIDC endpoint response is invalid")
	}
	return nil
}

func oidcHTTPClient(client *http.Client) *http.Client {
	copy := *client
	previousRedirect := client.CheckRedirect
	copy.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if validateEndpoint(request.URL.String()) != nil || len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && request.URL.Scheme != "https" {
			return errors.New("unsafe OIDC redirect")
		}
		if previousRedirect != nil {
			return previousRedirect(request, via)
		}
		if len(via) >= 10 {
			return errors.New("too many OIDC redirects")
		}
		return nil
	}
	return &copy
}

func verificationKey(token *jwt.Token, keys jwkSet) (any, error) {
	algorithm := token.Method.Alg()
	if !allowedSigningAlgorithm(algorithm) {
		return nil, errors.New("unsupported OIDC signing algorithm")
	}
	keyID, _ := token.Header["kid"].(string)
	var key any
	matches := 0
	for _, candidate := range keys.Keys {
		if keyID != "" && candidate.KeyID != keyID || candidate.Use != "" && candidate.Use != "sig" || candidate.Alg != "" && candidate.Alg != algorithm {
			continue
		}
		if len(candidate.KeyOps) != 0 && !contains(candidate.KeyOps, "verify") {
			continue
		}
		publicKey, err := candidate.publicKey(algorithm)
		if err != nil {
			continue
		}
		key = publicKey
		matches++
	}
	if matches != 1 {
		return nil, errors.New("OIDC signing key is missing or ambiguous")
	}
	return key, nil
}

func (key jwk) publicKey(algorithm string) (any, error) {
	if key.D != "" {
		return nil, errors.New("private key material is not accepted")
	}
	switch key.KeyType {
	case "RSA":
		if !isRSAAlgorithm(algorithm) {
			return nil, errors.New("RSA key does not match signing algorithm")
		}
		modulus, err := decodeBase64URL(key.N)
		if err != nil {
			return nil, err
		}
		exponent, err := decodeBase64URL(key.E)
		if err != nil || len(exponent) == 0 || len(exponent) > 4 {
			return nil, errors.New("invalid RSA exponent")
		}
		e := new(big.Int).SetBytes(exponent)
		if !e.IsInt64() || e.Int64() < 3 || e.Int64()%2 == 0 {
			return nil, errors.New("invalid RSA exponent")
		}
		n := new(big.Int).SetBytes(modulus)
		if n.BitLen() < 2048 {
			return nil, errors.New("RSA signing key is too small")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		if !isECDSAAlgorithm(algorithm) {
			return nil, errors.New("EC key does not match signing algorithm")
		}
		curve, expectedCurve := curveForAlgorithm(algorithm)
		if curve == nil || key.Curve != expectedCurve {
			return nil, errors.New("EC key curve does not match signing algorithm")
		}
		xBytes, err := decodeBase64URL(key.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := decodeBase64URL(key.Y)
		if err != nil {
			return nil, err
		}
		x, y := new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("invalid EC public key")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "OKP":
		if algorithm != jwt.SigningMethodEdDSA.Alg() || key.Curve != "Ed25519" {
			return nil, errors.New("OKP key does not match signing algorithm")
		}
		publicKey, err := decodeBase64URL(key.X)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 public key")
		}
		return ed25519.PublicKey(publicKey), nil
	default:
		return nil, errors.New("unsupported OIDC signing key type")
	}
}

func decodeBase64URL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("invalid OIDC signing key")
	}
	return decoded, nil
}

func allowedSigningAlgorithm(algorithm string) bool {
	return isRSAAlgorithm(algorithm) || isECDSAAlgorithm(algorithm) || algorithm == jwt.SigningMethodEdDSA.Alg()
}

func isRSAAlgorithm(algorithm string) bool {
	return algorithm == jwt.SigningMethodRS256.Alg() || algorithm == jwt.SigningMethodRS384.Alg() || algorithm == jwt.SigningMethodRS512.Alg() ||
		algorithm == jwt.SigningMethodPS256.Alg() || algorithm == jwt.SigningMethodPS384.Alg() || algorithm == jwt.SigningMethodPS512.Alg()
}

func isECDSAAlgorithm(algorithm string) bool {
	return algorithm == jwt.SigningMethodES256.Alg() || algorithm == jwt.SigningMethodES384.Alg() || algorithm == jwt.SigningMethodES512.Alg()
}

func curveForAlgorithm(algorithm string) (elliptic.Curve, string) {
	switch algorithm {
	case jwt.SigningMethodES256.Alg():
		return elliptic.P256(), "P-256"
	case jwt.SigningMethodES384.Alg():
		return elliptic.P384(), "P-384"
	case jwt.SigningMethodES512.Alg():
		return elliptic.P521(), "P-521"
	default:
		return nil, ""
	}
}

func issuerMatches(expectedIssuer, tokenIssuer, tenantID string) bool {
	if strings.Contains(expectedIssuer, "{tenantid}") {
		if !isUUID(tenantID) {
			return false
		}
		expectedIssuer = strings.ReplaceAll(expectedIssuer, "{tenantid}", tenantID)
	}
	return expectedIssuer == tokenIssuer
}

func isUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i, char := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func mapOIDCUser(rctx request.CTX, source userInfo, fallback *model.User, subject string, settings *model.SSOSettings) (*model.User, error) {
	if subject == "" {
		return nil, errors.New("OIDC subject is required")
	}
	username := ""
	if model.SafeDereference(settings.UsePreferredUsername) {
		username = preferredUsername(source.PreferredUsername)
	}
	if username == "" {
		username = source.Username
	}
	if username == "" && fallback != nil {
		username = fallback.Username
	}
	email := strings.TrimSpace(source.Email)
	if username == "" && email != "" {
		username = strings.SplitN(email, "@", 2)[0]
	}
	if username == "" && fallback != nil && fallback.Email != "" {
		username = strings.SplitN(fallback.Email, "@", 2)[0]
	}
	if username != "" {
		username = model.CleanUsername(rctx.Logger(), username)
	}

	user := &model.User{Username: username, AuthData: new(subject)}
	if source.GivenName != "" || source.FamilyName != "" {
		user.FirstName = source.GivenName
		user.LastName = source.FamilyName
	} else if source.Name != "" {
		setName(user, source.Name)
	} else if fallback != nil {
		user.FirstName = fallback.FirstName
		user.LastName = fallback.LastName
	}
	if source.Nickname != "" {
		user.Nickname = source.Nickname
	} else if fallback != nil {
		user.Nickname = fallback.Nickname
	}
	return user, nil
}

func preferredUsername(username string) string {
	if username == "" {
		return ""
	}
	return strings.SplitN(username, "@", 2)[0]
}

func setName(user *model.User, name string) {
	parts := strings.Fields(name)
	if len(parts) == 0 {
		return
	}
	user.FirstName = parts[0]
	if len(parts) > 1 {
		user.LastName = strings.Join(parts[1:], " ")
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
