package httpclient

import (
	"gocommon/jwt"
	"gocommon/tls"
	"os"
)

type ClientConfig struct {
	ServiceCN      string
	ServiceIP      string
	CertServiceURL string
	TLS            tls.TLSConfig
	Auth           *jwt.TokenAuthConfig
}

func DefaultConfig() ClientConfig {
	auth := jwt.DefaultAuthconfig()
	return ClientConfig{
		ServiceCN:      os.Getenv("SERVICE_CN"),
		ServiceIP:      os.Getenv("SERVICE_IP"),
		CertServiceURL: os.Getenv("CERTSERVICE_URL"),
		TLS:            tls.DefaultConfig(),
		Auth:           &auth,
	}
}
