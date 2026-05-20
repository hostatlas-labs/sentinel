// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

package alerter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WebhookPayload is the JSON structure sent to generic webhook endpoints.
type WebhookPayload struct {
	Host      string         `json:"host"`
	IP        string         `json:"ip"`
	Attempts  int            `json:"attempts"`
	Users     map[string]int `json:"users"`
	FirstSeen string         `json:"first_seen"`
	LastSeen  string         `json:"last_seen"`
	Timestamp string         `json:"timestamp"`
}

// GenericWebhook sends alerts to a user-defined HTTP endpoint.
type GenericWebhook struct {
	url     string
	method  string
	headers map[string]string
	client  *http.Client
}

// NewWebhook creates a new generic webhook alerter.
func NewWebhook(url, method string, headers map[string]string) *GenericWebhook {
	if method == "" {
		method = http.MethodPost
	}
	if headers == nil {
		headers = map[string]string{
			"Content-Type": "application/json",
		}
	}
	return &GenericWebhook{
		url:     url,
		method:  method,
		headers: headers,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Name returns the channel identifier.
func (w *GenericWebhook) Name() string { return "webhook" }

// Send delivers an alert to the configured webhook endpoint.
func (w *GenericWebhook) Send(ctx context.Context, alert *AlertMessage) error {
	payload := WebhookPayload{
		Host:      alert.Hostname,
		IP:        alert.IP,
		Attempts:  alert.Attempts,
		Users:     alert.Users,
		FirstSeen: alert.FirstSeen.UTC().Format(time.RFC3339),
		LastSeen:  alert.LastSeen.UTC().Format(time.RFC3339),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, w.method, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating webhook request: %w", err)
	}
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending webhook request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
