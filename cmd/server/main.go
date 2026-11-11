// Command server is the skylight-mcp Lambda entrypoint.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/logich/skylight-mcp-aws/internal/auth"
	"github.com/logich/skylight-mcp-aws/internal/calendar"
	"github.com/logich/skylight-mcp-aws/internal/canary"
	"github.com/logich/skylight-mcp-aws/internal/grant"
	"github.com/logich/skylight-mcp-aws/internal/lambdahttp"
	"github.com/logich/skylight-mcp-aws/internal/server"
	"github.com/logich/skylight-mcp-aws/internal/skylight"
	"github.com/logich/skylight-mcp-aws/internal/tools"
)

// version is set at build time: -ldflags "-X main.version=<git sha>".
var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	issuer := os.Getenv("AUTH_ISSUER")

	// Missing configuration is not fatal: auth fails closed, so every MCP
	// request is rejected until it is set.
	cal, tokens, err := skylightClient(context.Background())
	if err != nil {
		// Not fatal for the HTTP side: discovery and auth still work, and
		// Skylight-backed calls report the configuration error.
		logger.Error("skylight client not configured", "error", err.Error())
	}
	// Only a non-nil *calendar.Client goes into the interface (a typed nil
	// would look configured).
	var calendarIface tools.Calendar
	if cal != nil {
		calendarIface = cal
	}

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
		Calendar:     calendarIface,
	})
	httpHandler := lambdahttp.Handler(h)

	lambda.Start(func(ctx context.Context, raw json.RawMessage) (any, error) {
		if canary.IsCanary(raw) {
			if cal == nil {
				return canary.Result{Version: version, Stage: "config", ErrorClass: "other", Error: "skylight client not configured"}, nil
			}
			r := canary.Run(ctx, tokens, cal, version, time.Now())
			// Allowlisted fields only.
			logger.Info("canary", "ok", r.OK, "stage", r.Stage, "error_class", r.ErrorClass,
				"categories", r.Categories, "members", r.Members, "events_7_days", r.Events7Days,
				"token_ms", r.TokenMs, "total_ms", r.TotalMs)
			return r, nil
		}
		var ev events.APIGatewayV2HTTPRequest
		if err := json.Unmarshal(raw, &ev); err != nil {
			return events.APIGatewayV2HTTPResponse{StatusCode: http.StatusBadRequest, Body: "bad request"}, nil
		}
		return httpHandler(ctx, ev)
	})
}

// skylightClient builds the grant manager and calendar client from the
// environment (GRANT_TABLE) and the Lambda's role credentials.
func skylightClient(ctx context.Context) (*calendar.Client, *grant.Manager, error) {
	table := os.Getenv("GRANT_TABLE")
	if table == "" {
		return nil, nil, errors.New("GRANT_TABLE not set")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, nil, errors.New("loading AWS config failed")
	}
	tokens := &grant.Manager{
		Store:     grant.DynamoStore{API: dynamodb.NewFromConfig(cfg), Table: table},
		Refresher: skylight.TokenClient{},
	}
	return &calendar.Client{Tokens: tokens}, tokens, nil
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
