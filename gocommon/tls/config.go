package tls

import "os"

type TLSConfig struct {
	CertPath string
	KeyPath  string
	CAPath   string
}

func DefaultConfig() TLSConfig {
	cn := os.Getenv("SERVICE_CN")
	return TLSConfig{
		"/certs/" + cn + ".crt",
		"/certs/" + cn + ".key",
		"/certs/" + cn + "-ca.crt",
	}
}
