package httpclient

import (
	"context"
	"fmt"
	"gocommon/certclient"
	"gocommon/jwt"
	"gocommon/tls"
	"net/http"
	"os"
	"time"
)

type authTransport struct {
	token     string
	transport http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	return t.transport.RoundTrip(req)
}

func NewClient(cfg ClientConfig) (*http.Client, error) {
	_, err := os.ReadFile(cfg.TLS.CAPath)
	if err != nil {
		certclient.RecieveCertificates(cfg.CertServiceURL, cfg.ServiceCN, cfg.ServiceIP)
	}

	tlsConfig, err := tls.LoadTLSConfig(cfg.TLS.CertPath, cfg.TLS.KeyPath, cfg.TLS.CAPath, false)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	var finalTransport http.RoundTripper = transport
	if cfg.Auth != nil {
		tokenClientConfig := jwt.ClientConfig{Auth: *cfg.Auth, TLS: cfg.TLS}
		tokenClient, err := jwt.NewClient(&tokenClientConfig)
		if err != nil {
			return nil, fmt.Errorf("Error while creating token client: %w", err)
		}
		token, err := tokenClient.GetServiceToken(context.Background())
		if err != nil {
			return nil, fmt.Errorf("Error while fetching service token: %w", err)
		}
		newTransport := authTransport{
			token,
			transport,
		}
		finalTransport = &newTransport
	}

	return &http.Client{
		Transport: finalTransport,
		Timeout:   30 * time.Second,
	}, nil
}
