package certclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type Certificate struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	IssuingCA   string `json:"issuing_ca"`
	Serial      string `json:"serial"`
}

type CertificaServiceClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(certServiceURL string) *CertificaServiceClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &CertificaServiceClient{
		baseURL:    certServiceURL,
		httpClient: &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}
}

func (c *CertificaServiceClient) GetCA() ([]byte, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/ca")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CA: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch CA, status: %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (c *CertificaServiceClient) RequestCertificate(cn string, ips, dns []string, ttl string) (*Certificate, error) {
	reqData := map[string]any{
		"common_name": cn,
		"ips":         ips,
		"dns":         dns,
		"ttl":         ttl,
	}
	reqBody, _ := json.Marshal(reqData)
	resp, err := c.httpClient.Post(c.baseURL+"/issue", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to request certificate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to request certificate, status: %d, body: %s", resp.StatusCode, body)
	}
	var cert Certificate
	if err := json.NewDecoder(resp.Body).Decode(&cert); err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %w", err)
	}
	return &cert, nil
}

func SaveToFiles(cert *Certificate, baseName string) error {
	dir := "/certs/"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create certs directory: %w", err)
	}
	certPath := dir + baseName + ".crt"
	if err := os.WriteFile(certPath, []byte(cert.Certificate), 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}
	keyPath := dir + baseName + ".key"
	if err := os.WriteFile(keyPath, []byte(cert.PrivateKey), 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	caPath := dir + baseName + "-ca.crt"
	if err := os.WriteFile(caPath, []byte(cert.IssuingCA), 0644); err != nil {
		return fmt.Errorf("failed to save CA: %w", err)
	}
	return nil
}
