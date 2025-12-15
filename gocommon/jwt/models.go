package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type ServiceTokenClaims struct {
	ServiceName string `json:"service_name"`
	ServiceIP   string `json:"service_ip"`
	Certificate string `json:"certificate"` // Хеш сертификата
	// Standart claims
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`
	ID        string   `json:"jti"`
}

// GetNotBefore implements jwt.Claims.
func (s *ServiceTokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	if s.NotBefore == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(s.NotBefore, 0)), nil
}

// GetAudience implements jwt.Claims.
func (s *ServiceTokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings(s.Audience), nil
}

// GetExpirationTime implements jwt.Claims.
func (s *ServiceTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if s.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(s.ExpiresAt, 0)), nil
}

// GetIssuedAt implements jwt.Claims.
func (s *ServiceTokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if s.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(s.IssuedAt, 0)), nil
}

// GetIssuer implements jwt.Claims.
func (s *ServiceTokenClaims) GetIssuer() (string, error) {
	return s.Issuer, nil
}

// GetSubject implements jwt.Claims.
func (s *ServiceTokenClaims) GetSubject() (string, error) {
	return s.Subject, nil
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type PublicKeyResponse struct {
	KeyID     string `json:"kid"`
	PublicKey string `json:"public_key"`
	Algorithm string `json:"alg"`
	ExpiresAt int64  `json:"exp"`
}

type ValidationRequest struct {
	Token string `json:"token"`
}

type ValidationResponse struct {
	Valid  bool                `json:"valid"`
	Claims *ServiceTokenClaims `json:"claims,omitempty"`
	Error  string              `json:"error,omitempty"`
}

type TokenAuthConfig struct {
	TokenServiceURL string
	ServiceName     string
	ServiceIP       string
	PublicKeyTTL    time.Duration
	AllowedServices []string
	AllowedIssuer   string
}
