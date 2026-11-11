package skylight

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Response is a raw API answer. Body may hold family data: callers must not
// log it.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// APIClient makes authenticated read calls. Milestone 4 builds the real
// client (token store, lease, retries) on top of this.
type APIClient struct {
	HTTP    *http.Client // nil: 20 s timeout (as HA)
	BaseURL string       // empty: BaseURL
}

// GetOptions can drop the headers whose necessity is being probed.
type GetOptions struct {
	OmitUserAgent  bool
	OmitAPIVersion bool
}

// Get fetches path (e.g. "/api/frames") with query, using accessToken.
func (c APIClient) Get(ctx context.Context, accessToken, path string, query url.Values, o GetOptions) (Response, error) {
	base := c.BaseURL
	if base == "" {
		base = BaseURL
	}
	u := base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	if !o.OmitAPIVersion {
		req.Header.Set("Skylight-Api-Version", APIVersion)
	}
	if !o.OmitUserAgent {
		req.Header.Set("User-Agent", UserAgent)
	} else {
		req.Header.Set("User-Agent", "skylight-mcp")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("GET %s: request failed", path)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return Response{}, fmt.Errorf("GET %s: reading body", path)
	}
	return Response{Status: resp.StatusCode, Header: resp.Header, Body: b}, nil
}
