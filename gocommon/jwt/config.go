package jwt

import (
	"gocommon/tls"
	"os"
)

type TokenAuthConfig struct {
	TokenServiceURL string
	ServiceName     string
	ServiceIP       string
	AllowedServices *[]string
	AllowedIssuer   *string
}

func DefaultAuthconfig() TokenAuthConfig {
	return TokenAuthConfig{
		os.Getenv("TOKENSERVICE_URL"),
		os.Getenv("SERVICE_CN"),
		os.Getenv("SERVICE_IP"),
		nil,
		nil,
	}
}

type ClientConfig struct {
	Auth TokenAuthConfig
	TLS  tls.TLSConfig
}

func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		DefaultAuthconfig(),
		tls.DefaultConfig(),
	}
}
