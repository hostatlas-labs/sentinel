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

// Discord sends alerts to a Discord channel via a webhook.
type Discord struct {
	webhookURL string
	client     *http.Client
}

// NewDiscord creates a new Discord alerter.
func NewDiscord(webhookURL string) *Discord {
	return &Discord{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Name returns the channel identifier.
func (d *Discord) Name() string { return "discord" }

// Send delivers an alert to Discord using the webhook embeds format.
func (d *Discord) Send(ctx context.Context, alert *AlertMessage) error {
	userList := FormatUserList(alert.Users)
	duration := FormatDuration(alert.FirstSeen, alert.LastSeen)

	payload := map[string]interface{}{
		"username":   "Sentinel",
		"avatar_url": "https://raw.githubusercontent.com/hostatlas-labs/sentinel/main/.github/avatar.png",
		"embeds": []map[string]interface{}{
			{
				"title":       "\U0001f6a8 SSH Attack Detected",
				"color":       15158332, // Red (#E74C3C)
				"description": fmt.Sprintf("Brute-force attack detected on **%s**", alert.Hostname),
				"fields": []map[string]interface{}{
					{"name": "Attacker IP", "value": fmt.Sprintf("`%s`", alert.IP), "inline": true},
					{"name": "Failed Attempts", "value": fmt.Sprintf("%d in %s", alert.Attempts, duration), "inline": true},
					{"name": "Target Users", "value": userList, "inline": false},
					{"name": "First Seen", "value": alert.FirstSeen.UTC().Format(time.DateTime), "inline": true},
					{"name": "Last Seen", "value": alert.LastSeen.UTC().Format(time.DateTime), "inline": true},
				},
				"footer": map[string]interface{}{
					"text": "Sentinel — SSH & Login Attack Alerter",
				},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling discord payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating discord request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending discord request: %w", err)
	}
	defer resp.Body.Close()

	// Discord returns 204 No Content on success.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("discord returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
