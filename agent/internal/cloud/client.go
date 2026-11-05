// Package cloud is the agent side of the hosted control plane: credentials
// (pgsafe login), the agent API client, a durable outbox for run reports and
// the config/rules sync. Only metadata is ever sent (design doc §1, §3.10).
package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/desnarong/pgsafe/shared/apitypes"
)

// DefaultURL is the hosted control plane.
const DefaultURL = "https://app.pgsafe.dev"

const credFile = "cloud.json"

// Credentials link this agent to an org in the control plane.
type Credentials struct {
	URL       string `json:"url"`
	Token     string `json:"token"`
	AgentID   string `json:"agent_id,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
	OrgName   string `json:"org_name,omitempty"`
}

// LoadCredentials returns credentials from PGSAFE_CLOUD_TOKEN (+ PGSAFE_CLOUD_URL)
// or state_dir/cloud.json; nil when the agent is not logged in.
func LoadCredentials(stateDir string) (*Credentials, error) {
	if tok := os.Getenv("PGSAFE_CLOUD_TOKEN"); tok != "" {
		u := os.Getenv("PGSAFE_CLOUD_URL")
		if u == "" {
			u = DefaultURL
		}
		return &Credentials{URL: strings.TrimRight(u, "/"), Token: tok}, nil
	}
	data, err := os.ReadFile(filepath.Join(stateDir, credFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil || c.Token == "" || c.URL == "" {
		return nil, fmt.Errorf("%s is invalid; run pgsafe login again", credFile)
	}
	return &c, nil
}

// SaveCredentials writes state_dir/cloud.json with 0600 permissions.
func SaveCredentials(stateDir string, c *Credentials) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	p := filepath.Join(stateDir, credFile)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// RemoveCredentials deletes state_dir/cloud.json.
func RemoveCredentials(stateDir string) error {
	err := os.Remove(filepath.Join(stateDir, credFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Client talks to the agent API. Requests carry only the agent token and metadata.
type Client struct {
	base    string
	token   string
	version string
	http    *http.Client
}

func New(c *Credentials, version string) *Client {
	return &Client{base: strings.TrimRight(c.URL, "/"), token: c.Token, version: version, http: &http.Client{Timeout: 70 * time.Second}}
}

// APIError is a non-2xx response.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("control plane: HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// Permanent reports whether retrying the same request cannot succeed.
func (e *APIError) Permanent() bool {
	return e.Status >= 400 && e.Status < 500 && e.Status != http.StatusTooManyRequests && e.Status != http.StatusRequestTimeout
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", "pgsafe-agent/"+c.version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("control plane unreachable: %w", scrubURL(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
		return &APIError{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
	}
	return nil
}

func scrubURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func (c *Client) send(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	return c.do(ctx, method, path, body, out)
}

func (c *Client) Register(ctx context.Context, req apitypes.RegisterRequest) (*apitypes.RegisterResponse, error) {
	var out apitypes.RegisterResponse
	return &out, c.send(ctx, http.MethodPost, "/v1/agent/register", req, &out)
}

func (c *Client) Heartbeat(ctx context.Context, req apitypes.RegisterRequest) (*apitypes.HeartbeatResponse, error) {
	var out apitypes.HeartbeatResponse
	return &out, c.send(ctx, http.MethodPost, "/v1/agent/heartbeat", req, &out)
}

func (c *Client) Config(ctx context.Context) (*apitypes.ConfigResponse, error) {
	var out apitypes.ConfigResponse
	return &out, c.send(ctx, http.MethodGet, "/v1/agent/config", nil, &out)
}

// Commands long-polls for up to wait.
func (c *Client) Commands(ctx context.Context, wait time.Duration) ([]apitypes.Command, error) {
	var out apitypes.CommandsResponse
	err := c.send(ctx, http.MethodGet, fmt.Sprintf("/v1/agent/commands?wait=%d", int(wait.Seconds())), nil, &out)
	return out.Commands, err
}

func (c *Client) CommandDone(ctx context.Context, id string, res apitypes.CommandResult) error {
	return c.send(ctx, http.MethodPost, "/v1/agent/commands/"+url.PathEscape(id)+"/done", res, nil)
}
