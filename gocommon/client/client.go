package client

import (
	"gocommon/tls"
	"net/http"
	"os"
	"time"
)

type ClientConfg struct {
	CertPath string
	KeyPath  string
	CAPath   string
}

func DefaultConfig() ClientConfg {
	return ClientConfg{
		os.Getenv("TLS_CERT_PATH"),
		os.Getenv("TLS_KEY_PATH"),
		os.Getenv("TLS_CA_PATH"),
	}
}

func NewClient(cfg ClientConfg) (*http.Client, error) {
	tlsConfig, err := tls.LoadTLSConfig(cfg.CertPath, cfg.KeyPath, cfg.CAPath, false)

	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}
