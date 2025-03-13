package common

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/prov100/dc1/internal/config"
	partyproto "github.com/prov100/dc1/internal/protogen/party/v1"
	"github.com/rs/cors"
	"github.com/unrolled/secure"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

type Auth0Config struct {
	Port          string
	SecureOptions secure.Options
	CorsOptions   cors.Options
	Audience      string
	Domain        string
}

var log *zap.Logger

// DBMysql for DbType is mysql
const DBMysql string = "mysql"

// DBPgsql for DbType is pgsql
const DBPgsql string = "pgsql"

var jwtOpt *config.JWTOptions

// SetJWTOpt set JWT opt used in auth middleware
func SetJWTOpt(jwt *config.JWTOptions) {
	jwtOpt = jwt
}

// GetJWTOpt get JWT opt used in auth middleware
func GetJWTOpt() *config.JWTOptions {
	return jwtOpt
}

// GetAuthUserDetailsResponse - details of a user stored in the Redis cache
type GetAuthUserDetailsResponse struct {
	Email  string
	UserID string
	Roles  []string
}

// Key - type of the key used in the request context
type Key string

// KeyEmailToken - used for the request context key
const KeyEmailToken Key = "emailtoken"

// ContextStruct - stored in the request context
// set in AuthMiddleware
type ContextStruct struct {
	Email       string
	TokenString string
}

// GetAuthBearerToken - extract the BEARER token from the auth header
func GetAuthBearerToken(r *http.Request) (string, error) {
	var APIkey string
	bearer := r.Header.Get("authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		APIkey = bearer[7:]
	} else {
		log.Error("Error",
			zap.Int("msgnum", 252),
			zap.Error(errors.New("APIkey Not Found")))
		return "", errors.New("APIkey Not Found ")
	}
	return APIkey, nil
}

// GetJWTFromCtx - used to get jwt from context
func GetJWTFromCtx(ctx context.Context, header string) (string, error) {
	fmt.Println("auth.go GetJWTFromCtx header", header)
	fmt.Println("auth.go GetJWTFromCtx ctx", ctx)
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Error("Error", zap.Error(errors.New(`no headers in request`)))
		return "", errors.New("no headers in request")
	}

	authHeaders, ok := md[header]
	if !ok {
		log.Error("Error", zap.Error(errors.New(`no headers in request`)))
		return "", errors.New("no header in request")
	}

	if len(authHeaders) != 1 {
		log.Error("Error", zap.Error(errors.New(`more than 1 header in request`)))
		return "", errors.New("more than 1 header in request")
	}
	return authHeaders[0], nil
}

// CreateCtxJWT - used to get context
func CreateCtxJWT(ctx context.Context) (context.Context, error) {
	fmt.Println("auth.go CreateCtxJWT")
	fmt.Println("auth.go CreateCtxJWT ctx", ctx)
	auth, err := GetJWTFromCtx(ctx, "authorization")
	fmt.Println("auth.go CreateCtxJWT auth", auth)
	if err != nil {
		log.Error("Error", zap.Error(err))
		return ctx, err
	}
	md := metadata.Pairs("authorization", auth)
	fmt.Println("auth.go CreateCtxJWT md", md)
	newCtx := metadata.NewOutgoingContext(ctx, md)
	fmt.Println("auth.go CreateCtxJWT newCtx", newCtx)
	return newCtx, nil
}

// GetAuthData - used to get auth details
func GetAuthData(r *http.Request) ContextStruct {
	fmt.Println("internal/common/auth.go GetAuthData")
	fmt.Println("internal/common/auth.go GetAuthData r.Context()", r.Context())
	data := r.Context().Value(KeyEmailToken).(ContextStruct)
	fmt.Println("internal/common/auth.go GetAuthData data", data)
	return data
}

// GetProtoMd - used to get auth details and context
func GetProtoMd(r *http.Request) (context.Context, partyproto.GetAuthUserDetailsRequest) {
	fmt.Println("internal/common/auth.go GetProtoMd r", r)
	fmt.Println("internal/common/auth.go GetProtoMd call GetAuthData started")
	data := GetAuthData(r)
	fmt.Println("internal/common/auth.go GetProtoMd call GetAuthData ended")
	fmt.Println("internal/common/auth.go GetProtoMd data", data)
	cdata := partyproto.GetAuthUserDetailsRequest{}
	cdata.TokenString = data.TokenString
	cdata.Email = data.Email
	cdata.RequestUrlPath = r.URL.Path
	cdata.RequestMethod = r.Method
	fmt.Println("internal/common/auth.go GetProtoMd cdata", cdata)
	md := metadata.Pairs("authorization", "Bearer "+cdata.TokenString)
	fmt.Println("internal/common/auth.go GetProtoMd md", md)

	ctx := metadata.NewOutgoingContext(r.Context(), md)
	fmt.Println("internal/common/auth.go GetProtoMd ctx", md)
	return ctx, cdata
}

func ValidateToken(audience string, domain string) func(http.Handler) http.Handler {
	fmt.Println("internal/common/middleware.go ValidateToken1111")
	return func(next http.Handler) http.Handler {
		fmt.Println("internal/common/middleware.go ValidateToken2222")
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("r is", r)
			fmt.Println("internal/common/middleware.go ValidateToken3333")
			fmt.Println("internal/common/middleware.go audience is", audience)
			fmt.Println("internal/common/middleware.go domain is", domain)

			tokenString, err := getToken(r)
			if err != nil {
				http.Error(w, "Error parsing token", http.StatusUnauthorized)
				return
			}
			middleware, claims, err := getClaims(audience, domain, tokenString, w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			v := ContextStruct{}

			v.Email = claims.Email
			v.TokenString = tokenString

			fmt.Println("v.Email", v.Email)

			ctx := context.WithValue(r.Context(), KeyEmailToken, v)

			// middleware.CheckJWT(next).ServeHTTP(w, r)
			middleware.CheckJWT(next).ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func getToken(r *http.Request) (string, error) {
	authHeaderParts := strings.Fields(r.Header.Get("Authorization"))
	fmt.Println("internal/common/middleware.go authHeaderParts", authHeaderParts)
	fmt.Println("internal/common/middleware.go authHeaderParts[1]", authHeaderParts[1])
	if len(authHeaderParts) > 0 && strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Error parsing token")
	}
	return authHeaderParts[1], nil
}

func getClaims(audience string, domain string, tokenString string, w http.ResponseWriter, r *http.Request) (*jwtmiddleware.JWTMiddleware, *CustomClaims, error) {
	issuerURL, err := url.Parse("https://" + domain + "/")
	if err != nil {
		return nil, nil, errors.New("Failed to parse the issuer url")
	}
	fmt.Println("internal/common/middleware.go issuerURL is", issuerURL)

	provider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)
	// audience := "https://hello-world.example.com"
	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuerURL.String(),
		[]string{audience},
		validator.WithCustomClaims(func() validator.CustomClaims {
			return new(CustomClaims)
		}),
	)
	if err != nil {
		fmt.Println("Failed to set up the jwt validator")
		return nil, nil, errors.New("Failed to set up the jwt validator")
	}
	fmt.Println("internal/common/middleware.go ValidateToken4444444444")

	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		fmt.Println("Encountered error while validating JWT", err)
		if errors.Is(err, jwtmiddleware.ErrJWTMissing) {
			http.Error(w, "Error parsing token", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, jwtmiddleware.ErrJWTInvalid) {
			http.Error(w, "Error parsing token", http.StatusUnauthorized)
			return
		}
	}

	middleware := jwtmiddleware.New(
		jwtValidator.ValidateToken,
		jwtmiddleware.WithErrorHandler(errorHandler),
	)
	fmt.Println("internal/common/middleware.go ValidateToken middleware", middleware)
	fmt.Println("internal/common/middleware.go tokenString", tokenString)

	tokenClaims, err := jwtValidator.ValidateToken(r.Context(), tokenString)
	if err != nil {
		return nil, nil, err
	}
	m := tokenClaims.(*validator.ValidatedClaims)
	fmt.Println("tokenClaims.CustomClaims", m.CustomClaims)
	claims := m.CustomClaims.(*CustomClaims)
	fmt.Println("email is", claims.Email)
	return middleware, claims, nil
}
