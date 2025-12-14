package server

import (
	"fmt"
	"gocommon/certclient"
	"gocommon/tls"
	"net/http"
	"os"
)

type ServerConfig struct {
	ServiceCN      string
	ServiceIP      string
	CertServiceURL string
	CertPath       string
	KeyPath        string
	CAPath         string
}

func DefaultConfig() ServerConfig {
	cn := os.Getenv("SERVICE_CN")
	return ServerConfig{
		cn,
		os.Getenv("SERVICE_IP"),
		os.Getenv("CERTSERVICE_URL"),
		"/certs/" + cn + ".crt",
		"/certs/" + cn + ".key",
		"/certs/" + cn + "-ca.crt",
	}
}

func recieveCertificates(cfg *ServerConfig) error {
	client := certclient.NewClient(cfg.CertServiceURL)

	caData, err := client.GetCA()
	if err != nil {
		return fmt.Errorf("Warning: Failed to get CA: %v", err)
	} else {
		if err := os.WriteFile("/certs/ca.crt", caData, 0644); err != nil {
			return fmt.Errorf("Warning: Failed to save CA: %v", err)
		}
	}

	cert, err := client.RequestCertificate(
		cfg.ServiceCN,
		[]string{cfg.ServiceIP, "127.0.0.1", "::1"},
		[]string{
			cfg.ServiceCN,
			"localhost",
		},
		"720h",
	)
	if err != nil {
		return fmt.Errorf("Failed to request certificate: %v", err)
	}

	if err := certclient.SaveToFiles(cert, cfg.ServiceCN); err != nil {
		return fmt.Errorf("Failed to save certificate: %v", err)
	}
	return nil
}

func NewServer(cfg ServerConfig) (*http.Server, error) {
	_, err := os.ReadFile(cfg.CAPath)
	if err != nil {
		recieveCertificates(&cfg)
	}

	tlsConfig, err := tls.LoadTLSConfig(
		cfg.CertPath,
		cfg.KeyPath,
		cfg.CAPath,
		true,
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to load TLS config: %v", err)
	}

	return &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
	}, nil
}
