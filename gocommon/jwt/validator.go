package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

type Validator struct {
	config     *TokenAuthConfig
	httpClient *http.Client
	keysExpiry map[string]time.Time
}

func NewValidator(config *TokenAuthConfig) *Validator {
	v := &Validator{
		config: config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		keysExpiry: make(map[string]time.Time),
	}

	return v
}

func (v *Validator) fetchPublicKey(keyID string) (*rsa.PublicKey, error) {
	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/api/v1/jwt/keys/%s", v.config.TokenServiceURL, keyID),
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

	var keyResp PublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(keyResp.PublicKey))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPubKey, nil
}

func (v *Validator) ValidateToken(tokenString string) (*ServiceTokenClaims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("missing key ID in token header")
	}

	publicKey, err := v.fetchPublicKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	parsedToken, err := jwt.ParseWithClaims(tokenString, &ServiceTokenClaims{}, func(token *jwt.Token) (any, error) {
		// Проверяем алгоритм
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if claims, ok := parsedToken.Claims.(*ServiceTokenClaims); ok && parsedToken.Valid {
		if claims.Issuer != v.config.AllowedIssuer {
			return nil, errors.New("invalid issuer")
		}
		if len(v.config.AllowedServices) > 0 {
			allowed := slices.Contains(v.config.AllowedServices, claims.ServiceName)
			if !allowed {
				return nil, fmt.Errorf("service %s is not allowed", claims.ServiceName)
			}
		}
		return claims, nil
	}

	return nil, errors.New("invalid token claims")
}

func (v *Validator) ValidateRequest(r *http.Request) (*ServiceTokenClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errors.New("missing Authorization header")
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return nil, errors.New("invalid Authorization header format")
	}

	tokenString := authHeader[len(bearerPrefix):]

	return v.ValidateToken(tokenString)
}
