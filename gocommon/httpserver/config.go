package httpserver

import (
	"gocommon/jwt"
	"gocommon/tls"
	"os"
)

type ServerConfig struct {
	ServiceCN      string
	ServiceIP      string
	CertServiceURL string
	Tls            tls.TLSConfig
	Auth           *jwt.TokenAuthConfig
}

func DefaultConfig() ServerConfig {
	cn := os.Getenv("SERVICE_CN")
	auth := jwt.DefaultAuthconfig()
	return ServerConfig{
		cn,
		os.Getenv("SERVICE_IP"),
		os.Getenv("CERTSERVICE_URL"),
		tls.DefaultConfig(),
		&auth,
	}
}
