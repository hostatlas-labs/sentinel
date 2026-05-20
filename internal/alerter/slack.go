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

// Slack sends alerts to a Slack webhook.
type Slack struct {
	webhookURL string
	client     *http.Client
}

// NewSlack creates a new Slack alerter.
func NewSlack(webhookURL string) *Slack {
	return &Slack{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Name returns the channel identifier.
func (s *Slack) Name() string { return "slack" }

// Send delivers an alert to Slack using the Block Kit payload format.
func (s *Slack) Send(ctx context.Context, alert *AlertMessage) error {
	userList := FormatUserList(alert.Users)
	duration := FormatDuration(alert.FirstSeen, alert.LastSeen)

	payload := map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": "\U0001f6a8 SSH Attack Detected",
				},
			},
			{
				"type": "section",
				"fields": []map[string]interface{}{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Host:*\n%s", alert.Hostname)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Attacker IP:*\n`%s`", alert.IP)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Failed attempts:*\n%d in %s", alert.Attempts, duration)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Target users:*\n%s", userList)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*First seen:*\n%s", alert.FirstSeen.UTC().Format(time.DateTime))},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Last seen:*\n%s", alert.LastSeen.UTC().Format(time.DateTime))},
				},
			},
			{
				"type": "context",
				"elements": []map[string]interface{}{
					{"type": "mrkdwn", "text": "Sent by *Sentinel* — SSH & Login Attack Alerter"},
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending slack request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("slack returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
