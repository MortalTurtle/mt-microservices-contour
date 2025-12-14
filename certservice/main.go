package main

import (
	"crypto/tls"
	"crypto/x509"
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
		data["ip_sans"] = strings.Join(req.IPs, ",")
	}
	if len(req.DNS) > 0 {
		data["alt_names"] = strings.Join(req.DNS, ",")
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

func (vm *VaultManager) GetSelfCertificate() (*CertResponse, error) {
	serviceCN := os.Getenv("SERVICE_CN")
	if serviceCN == "" {
		return nil, fmt.Errorf("SERVICE_CN env is empty or missing")
	}

	serviceIP := os.Getenv("SERVICE_IP")
	if serviceIP == "" {
		serviceIP = "192.168.1.102"
	}

	req := CertRequest{
		CommonName: serviceCN,
		DNS: []string{
			serviceCN,
			"localhost",
		},
		IPs: []string{
			serviceIP,
			"127.0.0.1",
			"::1",
		},
		TTL: "8760h",
	}

	return vm.IssueCertificate(req)
}

func SaveCertificate(certResp *CertResponse, certPath, keyPath, caPath string) error {
	if err := os.WriteFile(certPath, []byte(certResp.Certificate), 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	if err := os.WriteFile(keyPath, []byte(certResp.PrivateKey), 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := os.WriteFile(caPath, []byte(certResp.IssuingCA), 0644); err != nil {
		return fmt.Errorf("failed to save CA: %w", err)
	}

	log.Printf("Certificate saved to: %s", certPath)
	log.Printf("Private key saved to: %s", keyPath)
	log.Printf("CA saved to: %s", caPath)

	return nil
}

func LoadTLSConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	var caCertPool *x509.CertPool
	if caPath != "" {
		caCert, err := os.ReadFile(caPath)
		if err == nil {
			caCertPool = x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, nil
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
	log.Println("Connected to Vault")

	certResp, err := vm.GetSelfCertificate()
	if err != nil {
		log.Fatalf("Warning: Failed to get self certificate: %v", err)
	} else {
		certPath := "/etc/vault/certservice.crt"
		keyPath := "/etc/vault/certservice.key"
		caPath := "/etc/vault/ca.crt"

		if err := SaveCertificate(certResp, certPath, keyPath, caPath); err != nil {
			log.Fatalf("Warning: Failed to save self certificate: %v", err)
		} else {
			log.Println("✓ Self certificate obtained and saved")
		}
	}

	http.HandleFunc("/issue", issueHandler(vm))
	http.HandleFunc("/health", healthHandler(vm))
	http.HandleFunc("/self", selfHandler(vm))
	http.HandleFunc("/ca", getCA())

	listenPort := ":8443"

	certPath := "/etc/vault/certservice.crt"
	keyPath := "/etc/vault/certservice.key"
	caPath := "/etc/vault/ca.crt"

	tlsConfig, err := LoadTLSConfig(certPath, keyPath, caPath)
	if err != nil {
		log.Fatalf("Cannot load TLS config: %v", err)
	}

	server := &http.Server{
		Addr:      listenPort,
		TLSConfig: tlsConfig,
	}

	log.Printf("Starting certservice on %s (TLS enabled)", listenPort)
	if err := server.ListenAndServeTLS(certPath, keyPath); err != nil {
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

func selfHandler(vm *VaultManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cert, err := vm.GetSelfCertificate()
		if err != nil {
			log.Printf("Error getting self certificate: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cert)
	}
}

func getCA() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caPath := "/etc/vault/ca.crt"
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			http.Error(w, "CA not available", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(caCert)
	}
}
