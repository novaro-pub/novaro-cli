// Package api is a small client of the NovaroPay merchant API: JSON over
// HTTPS, Bearer keys, the PSP-Version header and the API's error shape.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client calls one API host with one key (or none, for pairing).
type Client struct {
	Base       string // https://api.<host>
	Key        string
	Version    string // PSP-Version; "" is the account's default
	UserAgent  string
	HTTPClient *http.Client
}

// Error is the API's {"error": {...}} answer.
type Error struct {
	Status  int    `json:"-"`
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
	Param   string `json:"param,omitempty"`
	DocURL  string `json:"doc_url,omitempty"`
}

func (e *Error) Error() string {
	s := e.Message
	if s == "" {
		s = http.StatusText(e.Status)
	}
	if e.Code != "" {
		s += " (" + e.Code + ")"
	}
	return s
}

// Do sends method path with in as the JSON body (nil for none) and decodes
// a 2xx answer into out (nil to drop it). Any other answer is an *Error.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, header http.Header, in, out any) error {
	u := strings.TrimRight(c.Base, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.Key != "" {
		req.Header.Set("Authorization", "Bearer "+c.Key)
	}
	if c.Version != "" {
		req.Header.Set("PSP-Version", c.Version)
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		var env struct {
			Error *Error `json:"error"`
		}
		if json.Unmarshal(b, &env) == nil && env.Error != nil {
			env.Error.Status = res.StatusCode
			return env.Error
		}
		return &Error{Status: res.StatusCode, Message: fmt.Sprintf("%s: %s", res.Status, strings.TrimSpace(string(b)))}
	}
	if out == nil {
		return nil
	}
	if raw, ok := out.(*json.RawMessage); ok {
		*raw = append((*raw)[:0], b...)
		return nil
	}
	return json.Unmarshal(b, out)
}
