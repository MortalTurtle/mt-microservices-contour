package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type CertRequest struct {
	CommonName string   `json:"common_name"`
	IPs        []string `json:"ips,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	TTL        string   `json:"ttl,omitempty"`
}

type CertResponse struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	IssuingCA   string `json:"issuing_ca"`
	Serial      string `json:"serial"`
}

type VaultManager struct {
	client *vault.Client
}

func NewVaultManager() (*VaultManager, error) {
	config := vault.DefaultConfig()
	config.Address = os.Getenv("VAULT_ADDR")
	if caCertPath := os.Getenv("VAULT_CACERT"); caCertPath != "" {
		config.ConfigureTLS(&vault.TLSConfig{
			CACert: caCertPath,
		})
	}
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}
	roleID, err := os.ReadFile("/run/secrets/role_id")
	if err != nil {
		return nil, fmt.Errorf("failed to read role_id: %w", err)
	}
	secretID, err := os.ReadFile("/run/secrets/secret_id")
	if err != nil {
		return nil, fmt.Errorf("failed to read secret_id: %w", err)
	}
	data := map[string]any{
		"role_id":   strings.TrimSpace(string(roleID)),
		"secret_id": strings.TrimSpace(string(secretID)),
	}
	secret, err := client.Logical().Write("auth/approle/login", data)
	if err != nil {
		return nil, fmt.Errorf("AppRole login failed: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("no auth info in response")
	}
	client.SetToken(secret.Auth.ClientToken)
	log.Println("Logged in with AppRole")
	return &VaultManager{client: client}, nil
}

func (vm *VaultManager) IssueCertificate(req CertRequest) (*CertResponse, error) {
	data := map[string]any{
		"common_name": req.CommonName,
		"ttl":         req.TTL,
	}
	if len(req.IPs) > 0 {
		data["ip_sans"] = req.IPs
	}
	if len(req.DNS) > 0 {
		data["alt_names"] = req.DNS
	}
	secret, err := vm.client.Logical().Write("pki_internal/issue/certservice-role", data)
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}
	resp := &CertResponse{
		Certificate: secret.Data["certificate"].(string),
		PrivateKey:  secret.Data["private_key"].(string),
		IssuingCA:   secret.Data["issuing_ca"].(string),
		Serial:      secret.Data["serial_number"].(string),
	}
	return resp, nil
}

func (vm *VaultManager) HealthCheck() bool {
	status, err := vm.client.Sys().Health()
	return err == nil && !status.Sealed
}

func main() {
	for i := range 60 {
		if _, err := os.Stat("/run/secrets/role_id"); err == nil {
			log.Println("✓ Secrets found")
			break
		}
		log.Printf("Waiting for secrets... (%d/60)", i+1)
		time.Sleep(2 * time.Second)
	}
	vm, err := NewVaultManager()
	if err != nil {
		log.Fatalf("Failed to initialize Vault: %v", err)
	}
	if !vm.HealthCheck() {
		log.Fatal("Vault health check failed")
	}
	log.Println("✓ Connected to Vault")
	http.HandleFunc("/issue", issueHandler(vm))
	http.HandleFunc("/health", healthHandler(vm))
	log.Println("Starting certservice on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func issueHandler(vm *VaultManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req CertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.CommonName == "" {
			http.Error(w, "common_name is required", http.StatusBadRequest)
			return
		}
		if req.TTL == "" {
			req.TTL = "168h"
		}
		cert, err := vm.IssueCertificate(req)
		if err != nil {
			log.Printf("Error issuing certificate: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cert)
	}
}

func healthHandler(vm *VaultManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if vm.HealthCheck() {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status": "unavailable"}`))
		}
	}
}
