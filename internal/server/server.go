// Package server builds the HTTP handler: the OAuth discovery document, and the
// MCP endpoint behind the authorization check.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/logich/skylight-mcp-aws/internal/auth"
)

// Options configures the handler.
type Options struct {
	Auth auth.Config
	// AuthorizeURL and TokenURL are Cognito's hosted-UI OAuth endpoints. They
	// are advertised in the authorization-server metadata below; the server
	// never issues tokens itself.
	AuthorizeURL string
	TokenURL     string
	Version      string
	Logger       *slog.Logger
	Now          func() time.Time // defaults to time.Now
}

type helloOut struct {
	Message string `json:"message"`
	Version string `json:"version"`
}

// New returns the server's http.Handler.
func New(o Options) http.Handler {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}

	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return newMCPServer(o.Version)
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})

	mux := http.NewServeMux()
	// RFC 9728 protected-resource metadata, served unauthenticated. Both the
	// root and the path-suffixed forms are registered because clients differ.
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", protectedResource(o))
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", protectedResource(o))
	// Some clients look for authorization-server metadata on the resource's own
	// host (RFC 8414 / OIDC discovery) rather than following the pointer above.
	// Serve a description of Cognito's endpoints there. It only describes; it
	// issues nothing.
	for _, p := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-authorization-server/mcp",
		"/.well-known/openid-configuration",
		"/.well-known/openid-configuration/mcp",
	} {
		mux.HandleFunc("GET "+p, authorizationServer(o))
	}
	mux.Handle("/mcp", requireAuth(o, mcpHandler))
	return logRequests(o.Logger, mux)
}

func newMCPServer(version string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "skylight-mcp", Version: version}, nil)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "hello",
		Description: "Connectivity check. Returns a fixed greeting and the server build version.",
	}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, helloOut, error) {
		return nil, helloOut{Message: "hello from skylight-mcp", Version: version}, nil
	})
	return s
}

func protectedResource(o Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"resource": "https://" + r.Host + "/mcp",
			// This host is the declared authorization server: it serves the
			// metadata below (Cognito's endpoints). Pointing clients at
			// Cognito's issuer URL directly breaks clients that only try RFC 8414.
			"authorization_servers":    []string{"https://" + r.Host},
			"bearer_methods_supported": []string{"header"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=300")
		_ = json.NewEncoder(w).Encode(doc)
	}
}

func authorizationServer(o Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o.AuthorizeURL == "" || o.TokenURL == "" {
			http.NotFound(w, r)
			return
		}
		doc := map[string]any{
			// Must equal the authorization-server identifier clients used to
			// find this document (this host). Tokens are still issued, and
			// checked by auth.Authorize, under Cognito's own "iss".
			"issuer":                                "https://" + r.Host,
			"authorization_endpoint":                o.AuthorizeURL,
			"token_endpoint":                        o.TokenURL,
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
			"scopes_supported":                      []string{"openid", "email"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=300")
		_ = json.NewEncoder(w).Encode(doc)
	}
}

func requireAuth(o Options, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := auth.Authorize(o.Auth, auth.ClaimsFrom(r.Context()), o.Now()); err != nil {
			o.Logger.Warn("rejected", "reason", auth.Reason(err))
			w.Header().Set("WWW-Authenticate",
				`Bearer resource_metadata="https://`+r.Host+`/.well-known/oauth-protected-resource"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// logRequests logs method, path and status only: never headers, bodies,
// queries or claims.
func logRequests(l *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		l.Info("request", "method", r.Method, "path", r.URL.Path, "status", sw.status)
	})
}
