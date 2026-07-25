// Package seekrit is the read-path Go SDK for seekrit, the zero-knowledge
// secrets manager. Authenticate with a service token, resolve your
// environment, and get decrypted secrets — the API only ever returns
// ciphertext; decryption happens in your process.
//
//	client, err := seekrit.New()          // token from $SEEKRIT_TOKEN
//	secrets, err := client.Resolve(ctx)   // map[string]string
package seekrit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
)

// DefaultAPIURL is the hosted seekrit API base URL.
const DefaultAPIURL = "https://api.seekrit.dev"

type scope struct {
	OrgID   string `json:"orgId"`
	OrgSlug string `json:"orgSlug"`
	AppID   string `json:"appId"`
	AppSlug string `json:"appSlug"`
	EnvID   string `json:"envId"`
	EnvSlug string `json:"envSlug"`
}

type secretBlob struct {
	Name       string `json:"name"`
	Ciphertext string `json:"ciphertext"`
}

type layer struct {
	Source        string       `json:"source"`
	EnvironmentID string       `json:"environmentId"`
	Slug          string       `json:"slug"`
	GroupSlug     string       `json:"groupSlug,omitempty"`
	WrappedDEK    string       `json:"wrappedDek"`
	Secrets       []secretBlob `json:"secrets"`
}

type resolveResponse struct {
	Scope  scope   `json:"scope"`
	Layers []layer `json:"layers"`
}

// Client is a read-only seekrit client bound to one service token. It is safe
// for concurrent use.
type Client struct {
	token       string
	key         *tokenKey
	apiURL      string
	overrides   map[string]string
	httpClient  *http.Client
	interpolate bool
}

// Option configures a Client.
type Option func(*config)

type config struct {
	token       string
	apiURL      string
	overrides   map[string]string
	httpClient  *http.Client
	interpolate *bool
}

// WithToken sets the service token. Defaults to $SEEKRIT_TOKEN.
func WithToken(token string) Option { return func(c *config) { c.token = token } }

// WithAPIURL sets the API base URL. Defaults to $SEEKRIT_API_URL or
// https://api.seekrit.dev.
func WithAPIURL(apiURL string) Option { return func(c *config) { c.apiURL = apiURL } }

// WithOverrides sets {groupSlug: envSlug} overrides to pull a different
// environment slice of a composed group (the ?with= override).
func WithOverrides(overrides map[string]string) Option {
	return func(c *config) { c.overrides = overrides }
}

// WithHTTPClient sets a custom HTTP client (timeouts, proxies, transport).
func WithHTTPClient(hc *http.Client) Option { return func(c *config) { c.httpClient = hc } }

// WithInterpolate controls whether ${OTHER_SECRET} references in resolved
// values are expanded. It defaults to true; pass false to get the stored text
// verbatim.
func WithInterpolate(interpolate bool) Option {
	return func(c *config) { c.interpolate = &interpolate }
}

// New builds a Client, failing fast if no valid service token is available.
func New(opts ...Option) (*Client, error) {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}
	token := cfg.token
	if token == "" {
		token = os.Getenv("SEEKRIT_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("seekrit: no service token: use WithToken or set SEEKRIT_TOKEN")
	}
	key, err := parseTokenKey(token)
	if err != nil {
		return nil, err
	}
	apiURL := cfg.apiURL
	if apiURL == "" {
		apiURL = os.Getenv("SEEKRIT_API_URL")
	}
	if apiURL == "" {
		apiURL = DefaultAPIURL
	}
	hc := cfg.httpClient
	if hc == nil {
		hc = http.DefaultClient
	}
	interpolate := true
	if cfg.interpolate != nil {
		interpolate = *cfg.interpolate
	}
	return &Client{
		token:       token,
		key:         key,
		apiURL:      strings.TrimRight(apiURL, "/"),
		overrides:   cfg.overrides,
		httpClient:  hc,
		interpolate: interpolate,
	}, nil
}

// Resolve fetches, decrypts, and merges the token's environment, returning
// {NAME: value}. It is fail-closed: any resolve or decrypt failure returns an
// error rather than partial results.
func (c *Client) Resolve(ctx context.Context) (map[string]string, error) {
	resp, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}
	return materialize(resp, c.key, c.interpolate)
}

// Get resolves and returns a single secret's value; ok is false if the name is
// not present in the resolved environment.
func (c *Client) Get(ctx context.Context, name string) (value string, ok bool, err error) {
	merged, err := c.Resolve(ctx)
	if err != nil {
		return "", false, err
	}
	value, ok = merged[name]
	return value, ok, nil
}

func (c *Client) fetch(ctx context.Context) (*resolveResponse, error) {
	endpoint := c.apiURL + "/v1/resolve"
	if len(c.overrides) > 0 {
		groups := make([]string, 0, len(c.overrides))
		for g := range c.overrides {
			groups = append(groups, g)
		}
		sort.Strings(groups)
		q := url.Values{}
		for _, g := range groups {
			q.Add("with", g+":"+c.overrides[g])
		}
		endpoint += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("authorization", "Bearer "+c.token)
	req.Header.Set("accept", "application/json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("seekrit: resolve request failed: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("seekrit: reading resolve response failed: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, apiError(res.StatusCode, body)
	}
	var out resolveResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("seekrit: malformed resolve response: %w", err)
	}
	return &out, nil
}

func apiError(status int, body []byte) *APIError {
	e := &APIError{Status: status, Code: "internal", Message: fmt.Sprintf("HTTP %d", status)}
	var parsed struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &parsed) == nil && parsed.Error.Code != "" {
		e.Code = parsed.Error.Code
		e.Message = parsed.Error.Message
	}
	return e
}
