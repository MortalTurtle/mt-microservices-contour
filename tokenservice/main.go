package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gocommon/httpserver"
	jwtCommon "gocommon/jwt"
	"log"
	"net/http"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

type KeyPair struct {
	KeyID      string
	PrivateKey *rsa.PrivateKey
	CreatedAt  time.Time
}

type KeyStore struct {
	currentKey *KeyPair
	mu         sync.RWMutex
}

func NewKeyStore() (*KeyStore, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	keyPair := &KeyPair{
		KeyID:      fmt.Sprintf("key-%d", time.Now().Unix()),
		PrivateKey: privateKey,
		CreatedAt:  time.Now(),
	}

	return &KeyStore{
		currentKey: keyPair,
	}, nil
}

func (ks *KeyStore) GetCurrentKey() *KeyPair {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.currentKey
}

func (ks *KeyStore) GetPublicKeyPEM() (string, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.currentKey == nil {
		return "", false
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&ks.currentKey.PrivateKey.PublicKey)
	if err != nil {
		return "", false
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), true
}

type TokenService struct {
	keyStore *KeyStore
	server   *httpserver.Server
}

func NewTokenService() (*TokenService, error) {
	keyStore, err := NewKeyStore()
	if err != nil {
		return nil, err
	}

	return &TokenService{
		keyStore: keyStore,
	}, nil
}

type IssueTokenRequest struct {
	ServiceName string   `json:"service_name"`
	ServiceIP   string   `json:"service_ip"`
	Audience    []string `json:"audience,omitempty"`
}

func (ts *TokenService) issueTokenHandler(w http.ResponseWriter, r *http.Request) {
	clientCert := r.TLS.PeerCertificates[0]
	subject := clientCert.Subject.CommonName

	log.Printf("Token issue request from: %s", subject)

	var req IssueTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid request format"}`, http.StatusBadRequest)
		return
	}

	if req.ServiceName == "" {
		req.ServiceName = subject
	}

	if req.ServiceIP == "" {
		for _, ip := range clientCert.IPAddresses {
			req.ServiceIP = ip.String()
			break
		}
	}

	ttl := 3600

	currentKey := ts.keyStore.GetCurrentKey()
	if currentKey == nil {
		http.Error(w, `{"error": "No signing key available"}`, http.StatusInternalServerError)
		return
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(ttl) * time.Second)

	claims := &jwtCommon.ServiceTokenClaims{
		ServiceName: req.ServiceName,
		ServiceIP:   req.ServiceIP,
		Issuer:      "tokenservice.mt.ru",
		Subject:     req.ServiceName,
		Audience:    req.Audience,
		ExpiresAt:   expiresAt.Unix(),
		IssuedAt:    now.Unix(),
		ID:          fmt.Sprintf("jti-%d", now.UnixNano()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = currentKey.KeyID

	tokenString, err := token.SignedString(currentKey.PrivateKey)
	if err != nil {
		log.Printf("Failed to sign token: %v", err)
		http.Error(w, `{"error": "Failed to sign token"}`, http.StatusInternalServerError)
		return
	}

	response := jwtCommon.TokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   ttl,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("Issued token for service: %s", req.ServiceName)
}

func (ts *TokenService) jwksHandler(w http.ResponseWriter, r *http.Request) {
	currentKey := ts.keyStore.GetCurrentKey()
	if currentKey == nil {
		http.Error(w, `{"error": "No key available"}`, http.StatusInternalServerError)
		return
	}

	pubKeyPEM, exists := ts.keyStore.GetPublicKeyPEM()
	if !exists {
		http.Error(w, `{"error": "Failed to get public key"}`, http.StatusInternalServerError)
		return
	}

	response := map[string]any{
		"keys": []jwtCommon.KeyResponse{
			{
				KeyID:     currentKey.KeyID,
				PublicKey: pubKeyPEM,
				Algorithm: "RS256",
				ExpiresAt: 0,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (ts *TokenService) healthHandler(w http.ResponseWriter, r *http.Request) {
	currentKey := ts.keyStore.GetCurrentKey()
	keyStatus := "no_key"
	if currentKey != nil {
		keyStatus = currentKey.KeyID
	}

	response := map[string]any{
		"status":    "healthy",
		"service":   "tokenservice",
		"key":       keyStatus,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (ts *TokenService) startHealthServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", ts.healthHandler)
	go func() {
		log.Println("Health server starting on :8080")
		if err := http.ListenAndServe(":8080", mux); err != nil {
			log.Printf("Health server error: %v", err)
		}
	}()
}

func (ts *TokenService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method

	switch {
	case path == "/health" && method == "GET":
		ts.healthHandler(w, r)
	case path == "/.well-known/jwks.json" && method == "GET":
		ts.jwksHandler(w, r)
	case path == "/token/issue" && method == "POST":
		ts.issueTokenHandler(w, r)
	default:
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

func main() {
	service, err := NewTokenService()
	if err != nil {
		log.Fatalf("Failed to create token service: %v", err)
	}

	config := httpserver.DefaultConfig()
	config.Auth = nil

	server, err := httpserver.NewServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	service.server = server

	log.Println("Token service starting on :443")

	service.startHealthServer()
	if err := server.ListenAndServeWithHandler(service); err != nil {
		log.Fatal(err)
	}
}
