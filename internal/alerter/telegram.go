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

// Telegram sends alerts to a Telegram chat via the Bot API.
type Telegram struct {
	botToken string
	chatID   string
	client   *http.Client
}

// NewTelegram creates a new Telegram alerter.
func NewTelegram(botToken, chatID string) *Telegram {
	return &Telegram{
		botToken: botToken,
		chatID:   chatID,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Name returns the channel identifier.
func (t *Telegram) Name() string { return "telegram" }

// Send delivers an alert to a Telegram chat using the sendMessage API with
// HTML formatting.
func (t *Telegram) Send(ctx context.Context, alert *AlertMessage) error {
	userList := FormatUserList(alert.Users)
	duration := FormatDuration(alert.FirstSeen, alert.LastSeen)

	text := fmt.Sprintf(
		"<b>\U0001f6a8 SSH Attack Detected</b>\n\n"+
			"<b>Host:</b> %s\n"+
			"<b>Attacker IP:</b> <code>%s</code>\n"+
			"<b>Failed attempts:</b> %d in %s\n"+
			"<b>Target users:</b> %s\n"+
			"<b>First seen:</b> %s\n"+
			"<b>Last seen:</b> %s",
		alert.Hostname,
		alert.IP,
		alert.Attempts, duration,
		userList,
		alert.FirstSeen.UTC().Format(time.DateTime),
		alert.LastSeen.UTC().Format(time.DateTime),
	)

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)

	payload := map[string]interface{}{
		"chat_id":    t.chatID,
		"text":       text,
		"parse_mode": "HTML",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling telegram payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending telegram request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("telegram returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
