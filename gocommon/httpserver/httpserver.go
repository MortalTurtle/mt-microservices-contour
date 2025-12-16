package httpserver

import (
	"fmt"
	"gocommon/certclient"
	"gocommon/jwt"
	jwtauth "gocommon/middleware"
	"gocommon/tls"
	"net/http"
	"os"
)

type Server struct {
	authMiddleware *jwtauth.JWTMiddleware
	server         *http.Server
}

func NewServer(cfg ServerConfig) (*Server, error) {
	_, err := os.ReadFile(cfg.Tls.CAPath)
	if err != nil {
		certclient.RecieveCertificates(cfg.CertServiceURL, cfg.ServiceCN, cfg.ServiceIP)
	}

	tlsConfig, err := tls.LoadTLSConfig(
		cfg.Tls.CertPath,
		cfg.Tls.KeyPath,
		cfg.Tls.CAPath,
		true,
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to load TLS config: %v", err)
	}

	baseServer := http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
	}

	var middleware *jwtauth.JWTMiddleware = nil
	if cfg.Auth != nil {
		clientConfg := jwt.ClientConfig{
			Auth: *cfg.Auth,
			TLS:  cfg.Tls,
		}
		middleware, err = jwtauth.NewJWTMiddleware(clientConfg)
		if err != nil {
			return nil, fmt.Errorf("Failed to crate auth middleware: %v", err)
		}
	}
	server := Server{
		middleware,
		&baseServer,
	}

	return &server, nil
}

func (s *Server) Handler(h http.Handler) http.Handler {
	if s.authMiddleware != nil {
		return s.authMiddleware.Handler(h)
	}
	return h
}

func (s *Server) ListenAndServe() error {
	return s.server.ListenAndServeTLS("", "")
}

func (s *Server) ListenAndServeWithHandler(h http.Handler) error {
	s.server.Handler = s.Handler(h)
	return s.ListenAndServe()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.server.Handler != nil {
		s.server.Handler.ServeHTTP(w, r)
	} else {
		http.Error(w, "Handler not configured", http.StatusInternalServerError)
	}
}
