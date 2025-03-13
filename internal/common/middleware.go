package common

import (
	"context"
	"fmt"
	"net/http"
)

/*func Router(router *http.ServeMux) http.Handler {
	fmt.Println("common./middleware.go Router() started")
	fmt.Println("common./middleware.go Router() started router is", router)
	return HandleCacheControl(router)
}

func HandleCacheControl(next *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		fmt.Println("common./middleware.go HandleCacheControl() started rw is", rw)
		fmt.Println("common./middleware.go HandleCacheControl() started req is", req)
		headers := rw.Header()
		headers.Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
		headers.Set("Pragma", "no-cache")
		headers.Set("Expires", "0")
		next.ServeHTTP(rw, req)
	})
}*/

func HandleCacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set cache-control headers
		headers := w.Header()
		headers.Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
		headers.Set("Pragma", "no-cache")
		headers.Set("Expires", "0")

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers",
				"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Access-Control-Allow-Origin")
		}

		// Handle preflight OPTIONS requests
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Expose-Headers", "Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// AddMiddleware - adds middleware to a Handler
func AddMiddleware(h http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	for _, mw := range middleware {
		h = mw(h)
	}
	return h
}

// ChainMiddlewares - chains multiple middlewares together
func ChainMiddlewares(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(finalHandler http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			finalHandler = middlewares[i](finalHandler)
		}
		return finalHandler
	}
}

// CustomClaims contains custom data we want from the token.
type CustomClaims struct {
	Permissions []string `json:"permissions"`
	Email       string   `json:"email"`
}

// Validate does nothing for this example, but we need
// it to satisfy validator.CustomClaims interface.
func (c CustomClaims) Validate(ctx context.Context) error {
	return nil
}

func (c CustomClaims) HasPermissions(expectedClaims []string) bool {
	fmt.Println("internal/common/middleware.go HasPermissions() started")
	fmt.Println("internal/common/middleware.go HasPermissions() expectedClaims", expectedClaims)
	if len(expectedClaims) == 0 {
		return false
	}
	for _, scope := range expectedClaims {
		if !Contains(c.Permissions, scope) {
			return false
		}
	}
	fmt.Println("internal/common/middleware.go HasPermissions() ended")
	return true
}

func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func ValidatePermissions(expectedClaims []string, audience string, domain string) func(next http.Handler) http.Handler {
	fmt.Println("internal/common/middleware.go ValidatePermissions1111")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, err := getToken(r)
			if err != nil {
				http.Error(w, "Error parsing token", http.StatusUnauthorized)
				return
			}
			_, claims, err := getClaims(audience, domain, tokenString, w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			fmt.Println("claims", claims)
			fmt.Println("claims.Permissions", claims.Permissions)
			if len(claims.Permissions) == 0 {
				fmt.Println("in len(claims.Permissions) err is permission denied")
				RenderJSON(w, "Permission Denied")
				return
			}
			fmt.Println("ValidatePermissions111111")
			if !claims.HasPermissions(expectedClaims) {
				RenderJSON(w, "Permission Denied")
				return
			}
			fmt.Println("ValidatePermissions end")
			next.ServeHTTP(w, r)
		})
	}
}
