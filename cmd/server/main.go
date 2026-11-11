// Command server is the skylight-mcp Lambda entrypoint.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/logich/skylight-mcp-aws/internal/auth"
	"github.com/logich/skylight-mcp-aws/internal/lambdahttp"
	"github.com/logich/skylight-mcp-aws/internal/server"
)

// version is set at build time: -ldflags "-X main.version=<git sha>".
var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	issuer := os.Getenv("AUTH_ISSUER")

	// Missing configuration is not fatal: auth fails closed, so every MCP
	// request is rejected until it is set.
	h := server.New(server.Options{
		Auth: auth.Config{
			Issuer:     issuer,
			ClientID:   os.Getenv("AUTH_CLIENT_ID"),
			AllowedSub: os.Getenv("AUTH_ALLOWED_SUB"),
			Scope:      os.Getenv("AUTH_SCOPE"),
			Audience:   os.Getenv("AUTH_AUDIENCE"),
		},
		Keys: &auth.KeySet{
			Fetch:      jwksFetcher(issuer),
			MinRefresh: 30 * time.Second,
		},
		AuthorizeURL: os.Getenv("AUTH_AUTHORIZE_URL"),
		TokenURL:     os.Getenv("AUTH_TOKEN_URL"),
		Version:      version,
		Logger:       logger,
	})
	lambda.Start(lambdahttp.Handler(h))
}

// jwksFetcher returns a fetcher for the pool's published signing keys.
func jwksFetcher(issuer string) func(context.Context) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	return func(ctx context.Context) ([]byte, error) {
		if issuer == "" {
			return nil, errors.New("no issuer configured")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/jwks.json", nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("jwks: status %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	}
}
