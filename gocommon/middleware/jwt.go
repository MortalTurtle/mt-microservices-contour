package middleware

import (
	"context"
	"fmt"
	"gocommon/jwt"
	"net/http"
)

type contextKey string

const (
	ClaimsContextKey contextKey = "service_claims"
)

type JWTMiddleware struct {
	jwtClient *jwt.Client
}

func NewJWTMiddleware(cfg jwt.ClientConfig) (*JWTMiddleware, error) {
	client, err := jwt.NewClient(&cfg)
	if err != nil {
		return nil, fmt.Errorf("Error while creating jwt client: %w", err)
	}

	return &JWTMiddleware{
		client,
	}, nil
}

func (m *JWTMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := m.jwtClient.ValidateRequest(r)
		if err != nil {
			http.Error(w,
				`{"error": "Unauthorized", "message": "`+err.Error()+`"}`,
				http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
