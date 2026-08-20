package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestCORS(t *testing.T) {
	e := echo.New()

	// Wildcard origin
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	h := CORS()(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})

	// Simple request
	req.Header.Set(echo.HeaderOrigin, "localhost")
	h(c)
	assert.Equal(t, "localhost", rec.Header().Get(echo.HeaderAccessControlAllowOrigin))

	// Preflight request
	req = httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set(echo.HeaderOrigin, "localhost")
	req.Header.Set(echo.HeaderAccessControlRequestMethod, http.MethodGet)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h(c)
	assert.Equal(t, "localhost", rec.Header().Get(echo.HeaderAccessControlAllowOrigin))
	assert.NotEmpty(t, rec.Header().Get(echo.HeaderAccessControlAllowMethods))

	// Custom origin
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = CORSWithConfig(CORSConfig{
		AllowOrigins: []string{"localhost"},
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	req.Header.Set(echo.HeaderOrigin, "localhost")
	h(c)
	assert.Equal(t, "localhost", rec.Header().Get(echo.HeaderAccessControlAllowOrigin))

	// Custom origin (not allowed)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	req.Header.Set(echo.HeaderOrigin, "localhost1")
	h(c)
	assert.Empty(t, rec.Header().Get(echo.HeaderAccessControlAllowOrigin))

	// Preflight request (not allowed)
	req = httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set(echo.HeaderOrigin, "localhost1")
	req.Header.Set(echo.HeaderAccessControlRequestMethod, http.MethodGet)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h(c)
	assert.Empty(t, rec.Header().Get(echo.HeaderAccessControlAllowOrigin))

	// Preflight request (allowed)
	req = httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set(echo.HeaderOrigin, "localhost")
	req.Header.Set(echo.HeaderAccessControlRequestMethod, http.MethodGet)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h(c)
	assert.Equal(t, "localhost", rec.Header().Get(echo.HeaderAccessControlAllowOrigin))
	assert.NotEmpty(t, rec.Header().Get(echo.HeaderAccessControlAllowMethods))

	// Multiple origins
	h = CORSWithConfig(CORSConfig{
		AllowOrigins: []string{"localhost", "localhost1"},
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})

	// Multiple origins (allowed 1)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	req.Header.Set(echo.HeaderOrigin, "localhost")
	h(c)
	assert.Equal(t, "localhost", rec.Header().Get(echo.HeaderAccessControlAllowOrigin))

	// Multiple origins (allowed 2)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	req.Header.Set(echo.HeaderOrigin, "localhost1")
	h(c)
	assert.Equal(t, "localhost1", rec.Header().Get(echo.HeaderAccessControlAllowOrigin))

	// Multiple origins (not allowed)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	req.Header.Set(echo.HeaderOrigin, "localhost2")
	h(c)
	assert.Empty(t, rec.Header().Get(echo.HeaderAccessControlAllowOrigin))

	// Wildcard origin with credentials
	h = CORSWithConfig(CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowCredentials: true,
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	req.Header.Set(echo.HeaderOrigin, "localhost")
	h(c)
	assert.Equal(t, "localhost", rec.Header().Get(echo.HeaderAccessControlAllowOrigin))
	assert.Equal(t, "true", rec.Header().Get(echo.HeaderAccessControlAllowCredentials))

	// Subdomain wildcard origin
	h = CORSWithConfig(CORSConfig{
		AllowOrigins: []string{"http://*.example.com"},
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})

	// Subdomain wildcard origin (allowed 1)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	req.Header.Set(echo.HeaderOrigin, "http://sub.example.com")
	h(c)
	assert.Equal(t, "http://sub.example.com", rec.Header().Get(echo.HeaderAccessControlAllowOrigin))

	// Subdomain wildcard origin (allowed 2)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	req.Header.Set(echo.HeaderOrigin, "http://sub1.sub2.example.com")
	h(c)
	assert.Equal(t, "http://sub1.sub2.example.com", rec.Header().Get(echo.HeaderAccessControlAllowOrigin))

	// Subdomain wildcard origin (not allowed)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	req.Header.Set(echo.HeaderOrigin, "http://example.com")
	h(c)
	assert.Empty(t, rec.Header().Get(echo.HeaderAccessControlAllowOrigin))

	// Subdomain wildcard origin (not allowed 2)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	req.Header.Set(echo.HeaderOrigin, "http://sub.example.com.cn")
	h(c)
	assert.Empty(t, rec.Header().Get(echo.HeaderAccessControlAllowOrigin))

	// Expose headers
	h = CORSWithConfig(CORSConfig{
		ExposeHeaders: []string{echo.HeaderContentLength},
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	req.Header.Set(echo.HeaderOrigin, "localhost")
	h(c)
	assert.Equal(t, echo.HeaderContentLength, rec.Header().Get(echo.HeaderAccessControlExposeHeaders))

	// Max age
	h = CORSWithConfig(CORSConfig{
		MaxAge: 3600,
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	req = httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set(echo.HeaderOrigin, "localhost")
	req.Header.Set(echo.HeaderAccessControlRequestMethod, http.MethodGet)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h(c)
	assert.Equal(t, "3600", rec.Header().Get(echo.HeaderAccessControlMaxAge))
}

func TestCORS_PreflightAndOptions(t *testing.T) {
	e := echo.New()

	// 1. Valid Preflight Request
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set(echo.HeaderOrigin, "https://example.com")
	req.Header.Set(echo.HeaderAccessControlRequestMethod, http.MethodPost)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	h := CORS()(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	err := h(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "https://example.com", rec.Header().Get(echo.HeaderAccessControlAllowOrigin))

	// 2. Standard OPTIONS Request (Non-Preflight) - Missing Origin
	req = httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set(echo.HeaderAccessControlRequestMethod, http.MethodPost)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = CORS()(func(c echo.Context) error {
		return c.String(http.StatusOK, "custom options response")
	})
	err = h(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "custom options response", rec.Body.String())

	// 3. Standard OPTIONS Request (Non-Preflight) - Missing Access-Control-Request-Method
	req = httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set(echo.HeaderOrigin, "https://example.com")
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = CORS()(func(c echo.Context) error {
		return c.String(http.StatusOK, "custom options response")
	})
	err = h(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "custom options response", rec.Body.String())
}
