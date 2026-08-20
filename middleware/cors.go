package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
)

type (
	// CORSConfig defines the config for CORS middleware.
	CORSConfig struct {
		// Skipper defines a function to skip middleware.
		Skipper Skipper

		// AllowOrigins determines which origins are allowed for CORS.
		// Optional. Default value []string{"*"}.
		AllowOrigins []string `yaml:"allow_origins"`

		// AllowMethods determines which methods are allowed for CORS.
		// Optional. Default value DefaultCORSConfig.AllowMethods.
		AllowMethods []string `yaml:"allow_methods"`

		// AllowHeaders determines which headers are allowed for CORS.
		// Optional. Default value []string{}.
		AllowHeaders []string `yaml:"allow_headers"`

		// AllowCredentials indicates whether the request can include user credentials.
		// Optional. Default value false.
		AllowCredentials bool `yaml:"allow_credentials"`

		// ExposeHeaders indicates which headers are safe to expose to the API of a CORS API specification.
		// Optional. Default value []string{}.
		ExposeHeaders []string `yaml:"expose_headers"`

		// MaxAge indicates how long the results of a preflight request can be cached.
		// Optional. Default value 0.
		MaxAge int `yaml:"max_age"`
	}
)

var (
	// DefaultCORSConfig is the default CORS middleware config.
	DefaultCORSConfig = CORSConfig{
		Skipper:      DefaultSkipper,
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
	}
)

// CORS returns a Cross-Origin Resource Sharing (CORS) middleware.
func CORS() echo.MiddlewareFunc {
	return CORSWithConfig(DefaultCORSConfig)
}

// CORSWithConfig returns a CORS middleware with config.
func CORSWithConfig(config CORSConfig) echo.MiddlewareFunc {
	// Defaults
	if config.Skipper == nil {
		config.Skipper = DefaultSkipper
	}
	if len(config.AllowOrigins) == 0 {
		config.AllowOrigins = DefaultCORSConfig.AllowOrigins
	}
	if len(config.AllowMethods) == 0 {
		config.AllowMethods = DefaultCORSConfig.AllowMethods
	}

	allowMethods := strings.Join(config.AllowMethods, ", ")
	allowHeaders := strings.Join(config.AllowHeaders, ", ")
	exposeHeaders := strings.Join(config.ExposeHeaders, ", ")
	maxAge := strconv.Itoa(config.MaxAge)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			req := c.Request()
			res := c.Response()
			origin := req.Header.Get(echo.HeaderOrigin)
			allowOrigin := ""

			// Check allowed origins
			for _, o := range config.AllowOrigins {
				if o == "*" && config.AllowCredentials {
					allowOrigin = origin
					break
				}
				if o == "*" || o == origin {
					allowOrigin = o
					break
				}
				if matchScheme(o, origin) {
					allowOrigin = origin
					break
				}
			}

			// Simple request
			if req.Method != http.MethodOptions {
				res.Header().Add(echo.HeaderVary, echo.HeaderOrigin)
				if origin == "" || allowOrigin == "" {
					return next(c)
				}
				res.Header().Set(echo.HeaderAccessControlAllowOrigin, allowOrigin)
				if config.AllowCredentials {
					res.Header().Set(echo.HeaderAccessControlAllowCredentials, "true")
				}
				if exposeHeaders != "" {
					res.Header().Set(echo.HeaderAccessControlExposeHeaders, exposeHeaders)
				}
				return next(c)
			}

			// Preflight request
			if origin == "" || req.Header.Get(echo.HeaderAccessControlRequestMethod) == "" {
				return next(c)
			}

			res.Header().Add(echo.HeaderVary, echo.HeaderOrigin)
			res.Header().Add(echo.HeaderVary, echo.HeaderAccessControlRequestMethod)
			res.Header().Add(echo.HeaderVary, echo.HeaderAccessControlRequestHeaders)
			if allowOrigin == "" {
				return next(c)
			}
			res.Header().Set(echo.HeaderAccessControlAllowOrigin, allowOrigin)
			res.Header().Set(echo.HeaderAccessControlAllowMethods, allowMethods)
			if config.AllowCredentials {
				res.Header().Set(echo.HeaderAccessControlAllowCredentials, "true")
				}
			if allowHeaders != "" {
				res.Header().Set(echo.HeaderAccessControlAllowHeaders, allowHeaders)
			} else {
				h := req.Header.Get(echo.HeaderAccessControlRequestHeaders)
				if h != "" {
					res.Header().Set(echo.HeaderAccessControlAllowHeaders, h)
				}
			}
			if config.MaxAge > 0 {
				res.Header().Set(echo.HeaderAccessControlMaxAge, maxAge)
			}
			return c.NoContent(http.StatusNoContent)
		}
	}
}

func matchScheme(domain, origin string) bool {
	dLen := len(domain)
	oLen := len(origin)
	if dLen == 0 || oLen == 0 || dLen > oLen {
		return false
	}

	if domain[0] == '*' {
		return origin[oLen-dLen+1:] == domain[1:]
	}
	return false
}
