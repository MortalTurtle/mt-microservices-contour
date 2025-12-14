package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

type Certificate struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	IssuingCA   string `json:"issuing_ca"`
	Serial      string `json:"serial"`
}

func LoadTLSConfig(certPath, keyPath, caPath string, clientAuth bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if clientAuth {
		config.ClientCAs = caCertPool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		config.RootCAs = caCertPool
	}
	return config, nil
}
