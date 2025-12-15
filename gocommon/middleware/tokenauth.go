package tokenauth

import (
	"context"
	"gocommon/jwt"
	"net/http"
)

type contextKey string

const (
	ClaimsContextKey contextKey = "service_claims"
)

type Middleware struct {
	validator *jwt.Validator
}

func NewMiddleware(cfg jwt.TokenAuthConfig) *Middleware {
	return &Middleware{
		jwt.NewValidator(&cfg),
	}
}

// Handler возвращает http.Handler с проверкой JWT
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := m.validator.ValidateRequest(r)
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
