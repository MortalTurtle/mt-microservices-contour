package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gocommon/tls"
	"net/http"
	"slices"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

type Client struct {
	config     *TokenAuthConfig
	httpClient *http.Client
}

func NewClient(cfg *ClientConfig) (*Client, error) {
	tlsConfig, err := tls.LoadTLSConfig(cfg.TLS.CertPath, cfg.TLS.KeyPath, cfg.TLS.CAPath, false)
	if err != nil {
		return nil, fmt.Errorf("Error while creating token client: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	v := &Client{
		config:     &cfg.Auth,
		httpClient: &client,
	}
	return v, nil
}

func (v *Client) fetchPublicKey() (*rsa.PublicKey, error) {
	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/.well-known/jwks.json", v.config.TokenServiceURL),
		nil)
	if err != nil {
		return nil, err
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch key: %s", resp.Status)
	}

	var jwksResp JWKSResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwksResp); err != nil {
		return nil, err
	}

	if len(jwksResp.Keys) == 0 {
		return nil, fmt.Errorf("no keys found in JWKS response")
	}
	key := jwksResp.Keys[0]

	block, _ := pem.Decode([]byte(key.PublicKey))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPubKey, nil
}

func (v *Client) GetServiceToken(ctx context.Context) (string, error) {
	reqBody := IssueTokenRequest{
		ServiceName: v.config.ServiceName,
		Audience:    []string{"microservices"},
	}
	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/api/v1/token/issue", v.config.TokenServiceURL),
		strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get service token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth service returned status: %d", resp.StatusCode)
	}
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}
	return tokenResp.AccessToken, nil
}

func (v *Client) ValidateToken(tokenString string) (*ServiceTokenClaims, error) {

	publicKey, err := v.fetchPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	parsedToken, err := jwt.ParseWithClaims(tokenString, &ServiceTokenClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if claims, ok := parsedToken.Claims.(*ServiceTokenClaims); ok && parsedToken.Valid {
		if v.config.AllowedIssuer != nil && claims.Issuer != *v.config.AllowedIssuer {
			return nil, fmt.Errorf("invalid issuer")
		}
		if v.config.AllowedServices != nil {
			allowed := slices.Contains(*v.config.AllowedServices, claims.ServiceName)
			if !allowed {
				return nil, fmt.Errorf("service %s is not allowed", claims.ServiceName)
			}
		}
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

func (v *Client) ValidateRequest(r *http.Request) (*ServiceTokenClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return nil, fmt.Errorf("invalid Authorization header format")
	}

	tokenString := authHeader[len(bearerPrefix):]

	return v.ValidateToken(tokenString)
}
