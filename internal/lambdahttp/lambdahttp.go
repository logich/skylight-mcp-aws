// Package lambdahttp adapts an http.Handler to API Gateway HTTP API (payload
// format 2.0) events. It is small on purpose, so we do not need a third-party
// adapter module.
package lambdahttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-lambda-go/events"
)

// Handler returns a function suitable for lambda.Start.
func Handler(h http.Handler) func(context.Context, events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	return func(ctx context.Context, ev events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
		req, err := toRequest(ctx, ev)
		if err != nil {
			return events.APIGatewayV2HTTPResponse{StatusCode: http.StatusBadRequest, Body: "bad request"}, nil
		}
		w := &recorder{header: http.Header{}, status: http.StatusOK}
		h.ServeHTTP(w, req)
		return w.response(), nil
	}
}

func toRequest(ctx context.Context, ev events.APIGatewayV2HTTPRequest) (*http.Request, error) {
	body := []byte(ev.Body)
	if ev.IsBase64Encoded {
		var err error
		if body, err = base64.StdEncoding.DecodeString(ev.Body); err != nil {
			return nil, err
		}
	}

	// Deliberately ignored: ev.RequestContext.Authorizer. Claims in the event
	// are whatever the invoker put there; the server verifies the bearer token
	// in the Authorization header itself (internal/auth).

	u := url.URL{Path: ev.RawPath, RawQuery: ev.RawQueryString}
	req, err := http.NewRequestWithContext(ctx, ev.RequestContext.HTTP.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range ev.Headers {
		req.Header.Set(k, v)
	}
	req.Host = ev.RequestContext.DomainName
	req.ContentLength = int64(len(body))
	return req, nil
}

type recorder struct {
	header      http.Header
	status      int
	body        bytes.Buffer
	wroteHeader bool
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status, r.wroteHeader = code, true
	}
}

func (r *recorder) Write(p []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	return r.body.Write(p)
}

// Flush is a no-op: API Gateway HTTP APIs buffer the whole response, and the
// server runs the MCP transport in JSON-response mode, so nothing streams.
func (r *recorder) Flush() {}

func (r *recorder) response() events.APIGatewayV2HTTPResponse {
	headers := make(map[string]string, len(r.header))
	for k, v := range r.header {
		headers[strings.ToLower(k)] = strings.Join(v, ",")
	}
	resp := events.APIGatewayV2HTTPResponse{StatusCode: r.status, Headers: headers}
	if b := r.body.Bytes(); utf8.Valid(b) {
		resp.Body = string(b)
	} else {
		resp.Body = base64.StdEncoding.EncodeToString(b)
		resp.IsBase64Encoded = true
	}
	return resp
}
